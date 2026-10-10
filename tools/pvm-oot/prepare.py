#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Prepare a pinned OOT target; release orchestration belongs in the build repo."""
import argparse
from email import policy
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def validate_format_patch(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('patch must be a regular file: ' + path.name)
    message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    envelope = message.get_unixfrom() or ''
    body = message.get_payload(decode=True)
    if not (re.fullmatch(r'From (?:[0-9a-f]{40}|[0-9a-f]{64}) '
                         r'Mon Sep 17 00:00:00 2001', envelope)
            and message['From'] and message['Date']
            and str(message['Subject'] or '').startswith('[PATCH')
            and isinstance(body, bytes)
            and b'\n---\n' in body and b'\ndiff --git ' in body):
        raise ValueError('patch is not git format-patch mail: ' + path.name)


def tree_sha256(root, roots):
    """Hash paths and contents, including symlink targets, in sorted order."""
    paths = []
    for name in roots:
        path = root / name
        if path.is_dir():
            paths.extend(p for p in path.rglob('*') if p.is_symlink() or not p.is_dir())
        else:
            paths.append(path)
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda p: p.relative_to(root).as_posix()):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            kind = 'link'
            content = hashlib.sha256(os.readlink(path).encode()).hexdigest()
        else:
            kind = 'file'
            content = sha256(path)
        digest.update((name + '\0' + kind + '\0' + content + '\n').encode())
    return digest.hexdigest()


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def prepare(args):
    profile_path = args.profile.resolve()
    profile = json.loads(profile_path.read_text())
    if profile['format'] != 1:
        raise ValueError('unsupported profile format')
    build = args.kernel_build.resolve()
    target = profile['target']
    uts = (build / 'include/generated/utsrelease.h').read_text()
    if '#define UTS_RELEASE "' + target['kernel_release'] + '"' not in uts.splitlines():
        raise ValueError('target kernel release does not match profile')
    for name, expected in target['files_sha256'].items():
        if sha256(build / name) != expected:
            raise ValueError('target file does not match profile: ' + name)
    compiler = subprocess.check_output([args.cc, '--version'], text=True).splitlines()[0]
    if compiler != target['compiler_version']:
        raise ValueError('compiler does not match profile: ' + compiler)
    series_path = profile_path.parent / 'series'
    series = [s.strip() for s in series_path.read_text().splitlines()
              if s.strip() and not s.startswith('#')]
    if series != [p['file'] for p in profile['patches']]:
        raise ValueError('series order does not match profile')
    if len(set(series)) != len(series):
        raise ValueError('duplicate patch in series')
    patches = []
    for patch in profile['patches']:
        name = patch['file']
        if Path(name).name != name or not name.endswith('.patch'):
            raise ValueError('patch must be a local .patch file')
        path = profile_path.parent / name
        validate_format_patch(path)
        if sha256(path) != patch['sha256']:
            raise ValueError('patch checksum mismatch: ' + name)
        patches.append(path)
    output = args.output.absolute()
    if output.exists():
        raise ValueError('output already exists; choose a fresh directory')
    output.parent.mkdir(parents=True, exist_ok=True)
    source = profile['source']
    roots = source['export_roots']
    with tempfile.TemporaryDirectory(prefix='.pvm-oot-', dir=output.parent) as tmp:
        staging = Path(tmp) / 'source'
        staging.mkdir()
        if args.source:
            archive = Path(tmp) / 'source.tar'
            with archive.open('wb') as stream:
                run('git', '-C', str(args.source.resolve()), 'archive', '--format=tar',
                    source['commit'], *roots, stdout=stream)
            with tarfile.open(archive) as tar:
                # Only accept relative regular files/directories/symlinks from git.
                for member in tar.getmembers():
                    path = Path(member.name)
                    if path.is_absolute() or '..' in path.parts or not (
                            member.isfile() or member.isdir() or member.issym()):
                        raise ValueError('unsafe git archive member')
                    if member.issym():
                        target_path = Path(os.path.normpath(str(path.parent / member.linkname)))
                        if target_path.is_absolute() or target_path.parts[0] == '..':
                            raise ValueError('unsafe git archive symlink')
                tar.extractall(staging)
        else:
            export = args.source_export.resolve()
            if tree_sha256(export, roots) != source['export_tree_sha256']:
                raise ValueError('exported baseline checksum mismatch')
            for name in roots:
                src, dst = export / name, staging / name
                dst.parent.mkdir(parents=True, exist_ok=True)
                if src.is_dir():
                    shutil.copytree(src, dst, symlinks=True)
                else:
                    shutil.copy2(src, dst, follow_symlinks=False)
        if tree_sha256(staging, roots) != source['export_tree_sha256']:
            raise ValueError('baseline source does not match profile')
        apply_env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(staging.parent))
        for name in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE'):
            apply_env.pop(name, None)
        for patch in patches:
            run('git', 'apply', '--check', '--whitespace=error-all', str(patch),
                cwd=staging, env=apply_env)
            run('git', 'apply', '--whitespace=error-all', str(patch),
                cwd=staging, env=apply_env)
        manifest = {
            'profile': profile['name'], 'profile_sha256': sha256(profile_path),
            'source': source, 'patches': profile['patches'], 'target': target,
            'kernel_build': str(build), 'compiler_command': args.cc,
            'prepared_tree_sha256': tree_sha256(staging, roots),
        }
        (staging / '.pvm-oot-prepared.json').write_text(json.dumps(manifest, indent=2) + '\n')
        staging.rename(output)
    print(json.dumps({'source': str(output), 'manifest': str(output / '.pvm-oot-prepared.json')}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--source', type=Path, help='git repository containing the pinned baseline')
    group.add_argument('--source-export', type=Path, help='clean exported baseline, checked by content')
    parser.add_argument('--kernel-build', type=Path, required=True)
    parser.add_argument('--cc', default='gcc-15')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        prepare(args)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, 'pvm-oot: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
