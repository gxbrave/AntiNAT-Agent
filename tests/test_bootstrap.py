import os, pathlib, subprocess, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class BootstrapTests(unittest.TestCase):
 def run_script(self, args=(), identity=True, overrides=None):
  with tempfile.TemporaryDirectory() as tmp:
   p=pathlib.Path(tmp)
   (p/'curl').write_text('''#!/bin/bash
set -eu
[[ " $* " == *" --max-time "* && " $* " == *" --retry "* ]] || exit 88
url=""; out=""
while (($#)); do case "$1" in -o) out="$2"; shift 2;; https://*) url="$1"; shift;; *) shift;; esac; done
case "$url" in
 */libinstall.sh) printf '%s\\n' 'installer_run() { printf "ROLE=%s BASE=%s NODE=%s PIN=%s\\n" "$ANTINAT_ROLE" "$ANTINAT_RELEASE_BASE_URL" "$ANTINAT_NODE_ID" "$ANTINAT_CONTROLLER_PIN"; printf "ARG=%s\\n" "$@"; }' > "$out";;
 */release-ed25519.pub) touch "$out";; *) exit 90;; esac
''')
   (p/'curl').chmod(0o755)
   env=dict(os.environ,PATH=tmp+':'+os.environ['PATH'],ANTINAT_ROLE='both')
   env.update(overrides or {})
   env.pop('ANTINAT_NODE_ID',None); env.pop('ANTINAT_CONTROLLER_PIN',None)
   if identity: env.update(ANTINAT_NODE_ID='local-agent',ANTINAT_CONTROLLER_PIN='ab'*32)
   return subprocess.run(['bash',str(ROOT/'install.sh'),*args],env=env,text=True,capture_output=True)
 def test_agent_release_override_is_separate(self):
  args=['--controller-endpoint','http://127.0.0.1:3456']
  r=self.run_script(args,overrides={'ANTINAT_RELEASE_BASE_URL':'https://controller.invalid/release','ANTINAT_AGENT_RELEASE_BASE_URL':'https://mirror.example/https://github.com/gxbrave/AntiNAT-Agent/releases/download/v1.0.0-beta.3'})
  self.assertEqual(r.returncode,0,r.stderr)
  self.assertIn('BASE=https://mirror.example/',r.stdout)
  self.assertNotIn('controller.invalid',r.stdout)
  for url in ['http://unsafe.example','https://user@host/path','https://host/path?query=1']:
   r=self.run_script(args,overrides={'ANTINAT_AGENT_RELEASE_BASE_URL':url})
   self.assertEqual(r.returncode,2,r.stderr)
 def test_requires_controller_identity(self):
  r=self.run_script(['--controller-endpoint','http://127.0.0.1:3456'],False)
  self.assertEqual(r.returncode,2,r.stderr)
 def test_requires_endpoint(self):
  r=self.run_script(); self.assertEqual(r.returncode,2,r.stderr)
 def test_parameterized_agent_only(self):
  r=self.run_script(['install','--platform','linux','--controller-endpoint','http://127.0.0.1:3456','--token-file','/secure/token'])
  self.assertEqual(r.returncode,0,r.stderr)
  self.assertIn('ROLE=agent',r.stdout)
  self.assertIn('AntiNAT-Agent/releases/download/v1.0.0-beta.3',r.stdout)
  self.assertIn('ARG=/secure/token',r.stdout)
 def test_rejects_role_and_literal_token(self):
  for args in [['--role','controller'],['--token','secret']]:
   r=self.run_script(['--controller-endpoint','http://127.0.0.1:3456',*args]); self.assertEqual(r.returncode,2,r.stderr)
 def test_purge_removes_agent_runtime_files(self):
  with tempfile.TemporaryDirectory() as tmp:
   state=pathlib.Path(tmp)/'var/lib/antinat'
   state.mkdir(parents=True)
   (state/'detection.profile').write_text('cached')
   (state/'.enrollment-token').write_text('stale')
   env=dict(os.environ,ANTINAT_TEST_ROOT=tmp,ANTINAT_TEST_MODE='1',ANTINAT_ROLE='agent')
   r=subprocess.run(['bash','-c','source "$1"; set +e; installer_run purge; exit "$?"',
                     'test',str(ROOT/'scripts/libinstall.sh')],env=env,capture_output=True,text=True)
   self.assertEqual(r.returncode,7,r.stderr)
   self.assertFalse((state/'detection.profile').exists())
   self.assertFalse((state/'.enrollment-token').exists())
if __name__=='__main__': unittest.main()
