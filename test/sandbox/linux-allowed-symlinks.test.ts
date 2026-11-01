import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  cleanupBwrapMountPoints,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import {
  countMounts,
  indexOfMount,
  lastIndexOfMount,
} from '../helpers/bwrap-argv.js'

describe.if(isLinux)('Linux explicitly allowed symlinks', () => {
  const canNamespace = bwrapCanNamespace()
  let base: string
  let run: string
  let store: string
  let system: string
  let link: string

  beforeEach(() => {
    base = realpathSync(mkdtempSync(join(tmpdir(), 'allowed-symlinks-')))
    run = join(base, 'run')
    store = join(base, 'store')
    system = join(store, 'system')
    link = join(run, 'current-system')
    mkdirSync(run)
    mkdirSync(join(system, 'sw', 'bin'), { recursive: true })
    symlinkSync(system, link)
    writeFileSync(join(run, 'private'), 'PRIVATE')
    writeFileSync(join(system, 'secret'), 'SECRET')
    symlinkSync(process.execPath, join(system, 'sw', 'bin', 'hello'))
  })

  afterEach(() => {
    cleanupBwrapMountPoints({ force: true })
    rmSync(base, { recursive: true, force: true })
  })

  async function wrap(
    allowRead = [store, link],
    denyRead = [run, store],
    command = 'echo ok',
    denyWrite: string[] = [],
  ) {
    return wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      readConfig: { denyOnly: denyRead, allowWithinDeny: allowRead },
      writeConfig: { allowOnly: [], denyWithinAllow: denyWrite },
    })
  }

  it('recreates the explicitly allowed alias after masking its parent', async () => {
    const command = await wrap()
    expect(countMounts(command, '--symlink', system, link)).toBe(1)
    expect(indexOfMount(command, '--symlink', system, link)).toBeGreaterThan(
      indexOfMount(command, '--tmpfs', run),
    )
    expect(countMounts(command, '--ro-bind', run, run)).toBe(0)
    expect(countMounts(command, '--ro-bind', system, link)).toBe(0)
  })

  it('also preserves the alias with a root deny', async () => {
    // Separate root children need separate masks. With both names under the
    // same masked directory, the existing carve-out bind suffices.
    const target = realpathSync(
      mkdtempSync(join(process.cwd(), '.allowed-symlinks-')),
    )
    const alias = join(run, 'root-alias')
    symlinkSync(target, alias)
    try {
      const command = await wrap([target, alias], ['/'])
      expect(countMounts(command, '--symlink', target, alias)).toBe(1)
    } finally {
      rmSync(target, { recursive: true, force: true })
    }
  })

  it('does not recreate an alias based only on its own target grant', async () => {
    const command = await wrap([link])
    expect(command).not.toContain('--symlink')
  })

  it('does not recreate links to denied files', async () => {
    const secretLink = join(run, 'secret')
    const secret = join(system, 'secret')
    symlinkSync(secret, secretLink)
    const command = await wrap([store, secretLink], [run, store, secret])
    expect(command).not.toContain('--symlink')
  })

  it('does not recreate links whose targets remain hidden', async () => {
    const command = await wrap([link], [run, store, system])
    expect(command).not.toContain('--symlink')
  })

  it('does not recreate dangling links or cycles', async () => {
    const dangling = join(run, 'dangling')
    const cycle = join(run, 'cycle')
    symlinkSync(join(store, 'missing'), dangling)
    symlinkSync(cycle, cycle)
    const command = await wrap([store, dangling, cycle])
    expect(command).not.toContain('--symlink')
  })

  it('does not recreate an unlisted sibling symlink', async () => {
    const sibling = join(run, 'sibling')
    symlinkSync(system, sibling)
    const command = await wrap()
    expect(countMounts(command, '--symlink', system, link)).toBe(1)
    expect(countMounts(command, '--symlink', system, sibling)).toBe(0)
  })

  it('does not restore links beneath a deny directory that could not be listed', async () => {
    const command = await wrapCommandWithSandboxLinux({
      command: 'echo ok',
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      readConfig: {
        denyOnly: [run, store],
        allowWithinDeny: [store, link],
        unlistableDenyDirs: [run],
      },
      writeConfig: { allowOnly: [], denyWithinAllow: [] },
    })
    expect(command).not.toContain('--symlink')
  })

  it('does not recreate aliases inside a credential-denied directory', async () => {
    const command = await wrapCommandWithSandboxLinux({
      command: 'echo ok',
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      readConfig: {
        denyOnly: [run, store],
        credentialDenyOnly: [run],
        allowWithinDeny: [store, link],
      },
      writeConfig: { allowOnly: [], denyWithinAllow: [] },
    })
    expect(command).not.toContain('--symlink')
  })

  it('does not recreate a link to a masked credential file', async () => {
    const secret = join(system, 'secret')
    const alias = join(run, 'credential')
    const fake = join(base, 'fake')
    writeFileSync(fake, 'MASKED')
    symlinkSync(secret, alias)
    const command = await wrapCommandWithSandboxLinux({
      command: 'echo ok',
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      readConfig: {
        denyOnly: [run, store],
        allowWithinDeny: [store, alias],
      },
      writeConfig: { allowOnly: [], denyWithinAllow: [] },
      maskedFileBinds: [{ realPath: secret, fakePath: fake }],
    })
    expect(command).not.toContain('--symlink')
  })

  it('keeps descendant restores at the target rather than the alias', async () => {
    const child = join(link, 'sw')
    const command = await wrap([store, link, child])
    const targetChild = join(system, 'sw')
    expect(countMounts(command, '--ro-bind', targetChild, targetChild)).toBe(1)
    expect(countMounts(command, '--symlink', system, link)).toBe(1)
  })

  it('keeps target-side directory denies in place', async () => {
    const denied = join(system, 'sw')
    const command = await wrap([store, link], [run, store, denied])
    expect(countMounts(command, '--symlink', system, link)).toBe(1)
    expect(countMounts(command, '--tmpfs', denied)).toBe(1)
    expect(countMounts(command, '--ro-bind', system, link)).toBe(0)
  })

  it('leaves already visible links alone', async () => {
    const command = await wrap([store, link], [store])
    expect(command).not.toContain('--symlink')
  })

  it('accepts targets already readable without an explicit target grant', async () => {
    const command = await wrap([link], [run])
    expect(countMounts(command, '--symlink', system, link)).toBe(1)
  })

  it('resolves relative multi-hop targets without exposing intermediate links', async () => {
    const hop = join(run, 'hop')
    symlinkSync('../store/system', hop)
    const alias = join(run, 'alias')
    symlinkSync('hop', alias)
    const command = await wrap([store, alias, alias])
    expect(countMounts(command, '--symlink', system, alias)).toBe(1)
    expect(countMounts(command, '--symlink', system, hop)).toBe(0)
  })

  it('recreates links after a denyWrite bind re-applies the parent tmpfs', async () => {
    const command = await wrap([store, link], [run, store], 'echo ok', [base])
    expect(indexOfMount(command, '--symlink', system, link)).toBeGreaterThan(
      lastIndexOfMount(command, '--tmpfs', run),
    )
  })

  it.if(canNamespace)(
    'executes via the alias without exposing siblings (live bwrap)',
    async () => {
      const command = await wrap(
        [store, link],
        [run, store, join(system, 'secret')],
        `${link}/sw/bin/hello -e 'console.log("ALIAS_OK")'; test ! -e ${run}/private && test ! -s ${link}/secret && echo DENIES_OK`,
      )
      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 15000,
      })
      expect(result.status).toBe(0)
      expect(result.stdout).toContain('ALIAS_OK')
      expect(result.stdout).toContain('DENIES_OK')
    },
  )
})
