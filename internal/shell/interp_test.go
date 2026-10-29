package shell

import (
	"strings"
	"testing"
)

// The four Python bodies Claude Code ran in the agent-driven trial of
// 2026-10-29 (abbreviated): each edits a .tf or .hcl file and mentions
// terraform or terragrunt only as text.
var trialEdits = []string{
	// cloud-platform-infrastructure: pin launch template names in cluster.tf.
	"python3 -I - <<'EOF'\nimport re\np='cluster.tf'\ns=open(p).read()\npins={'def':'default_ng_19_06_26','mon':'monitoring_ng_19_06_26'}\nfor short,key in pins.items():\n    pat=re.compile(r'(    name       = \"\\$\\{terraform\\.workspace\\}-%s-ng\"\\n)'%short)\n    assert len(pat.findall(s))==1,short\n    s=pat.sub(r'\\1    launch_template_name = \"%s\"\\n'%key,s)\nopen(p,'w').write(s)\nEOF\nterraform fmt -no-color cluster.tf moved.tf; git diff cluster.tf",
	// cloud-platform-infrastructure: rename node group map keys.
	"python3 -I - <<'EOF'\nimport re\np='cluster.tf'\ns=open(p).read()\nassert s.count('${terraform.workspace}-def-ng')==1\nhead,tail=s.split('  eks_managed_node_groups = merge(',1)\nblock,rest=tail.split('\\n  )\\n',1)\nfor k in ['default_ng_19_06_26']:\n    block=re.sub(r'\\b%s( *)= local\\.'%k, lambda m:k.replace('_','-')+m.group(1)+'= local.', block)\nopen(p,'w').write(head+'  eks_managed_node_groups = merge('+block+'\\n  )\\n'+rest)\nEOF",
	// terragrunt-infrastructure-live-example: switch root.hcl to a local backend.
	"python3 -I - <<'EOF'\nimport re\np='root.hcl'\ns=open(p).read()\nstart=s.index('remote_state {')\nend=s.index('# Configure what repos')\ns=s[:start]+'''remote_state {\n  backend = \"local\"\n  config = {\n    path = \"${get_terragrunt_dir()}/terraform.tfstate\"\n  }\n}\n\n'''+s[end:]\nopen(p,'w').write(s)\nEOF",
	// terragrunt-infrastructure-live-example: add inputs to a copied terragrunt.hcl.
	"python3 -I - <<'EOF'\np='mysql-replica/terragrunt.hcl'\ns=open(p).read()\ni=s.index('# ----', s.index('terraform {'))\ns=s[:i]+'''inputs = {\n  name = \"mysql_replica_${include.envcommon.locals.env}\"\n}\n'''\nopen(p,'w').write(s)\nEOF\ntail -12 mysql-replica/terragrunt.hcl",
}

func TestFileOnlyInterpreterBodies(t *testing.T) {
	fs := fakeFS(map[string]string{
		"/repo/fix.py":  "import re\np='main.tf'\ns=open(p).read()\nopen(p,'w').write(re.sub('terraform','tofu',s))\n",
		"/repo/fix.js":  "const fs=require('node:fs');let s=fs.readFileSync('main.tf','utf8');fs.writeFileSync('main.tf',s.replace(/terraform/g,'tofu'));\n",
		"/repo/body.py": "s=open('main.tf').read()\nopen('main.tf','w').write(s.replace('terraform','tofu'))\n",
	})
	type tc struct {
		name, cmd string
		note      bool   // a file-edit note is expected and no problem
		reason    string // substring of the problem reason otherwise
	}
	cases := []tc{
		{"trial edit 1", trialEdits[0], true, ""},
		{"trial edit 2", trialEdits[1], true, ""},
		// Trial edit 3 inserts an HCL block that names terraform.tfstate: a
		// state file named anywhere in the body keeps the ask (review of PR #31).
		{"trial edit 3 names .tfstate in an HCL string", trialEdits[2], false, "names the state file"},
		{"trial edit 4", trialEdits[3], true, ""},
		{"script file", "python3 fix.py", true, ""},
		{"script file with plain arguments", "python3 fix.py cluster.tf", true, ""},
		{"stdin from a file", "python3 - < body.py", true, ""},
		{"-c literal", `python3 -c "s=open('main.tf').read(); open('main.tf','w').write(s.replace('terraform','tofu'))"`, true, ""},
		{"node -e", `node -e "const fs=require('fs');let s=fs.readFileSync('main.tf','utf8');s=s.replace(/terraform\.workspace/g,'x');fs.writeFileSync('main.tf',s)"`, true, ""},
		{"node script with regex exec", "node fix.js", true, ""},
		{"python regex compile is not the builtin", "python3 -c \"import re; p=re.compile('terraform'); open('a.tf','w').write(p.sub('tofu', open('a.tf').read()))\"", true, ""},

		// The same edit plus a way to run something: still asked.
		{"subprocess", "python3 -I - <<'EOF'\nimport re, subprocess\np='cluster.tf'\ns=open(p).read()\nopen(p,'w').write(s)\nsubprocess.run(['terraform','destroy','-auto-approve'])\nEOF", false, "uses subprocess"},
		{"os.system built from pieces", "python3 -I - <<'EOF'\nimport os\ngetattr(os,'sys'+'tem')('terra'+'form destroy -auto-approve')\nEOF", false, "uses getattr()"},
		{"aliased os module", "python3 -I - <<'EOF'\nimport os as o\no.system('terraform destroy')\nEOF", false, "uses system()"},
		{"from os import", "python3 -I - <<'EOF'\nfrom os import system\nsystem('terraform destroy')\nEOF", false, "uses system()"},
		{"__import__", "python3 -c \"__import__('os').system('terraform destroy')\"", false, "uses __import__"},
		{"importlib", "python3 -c \"import importlib; importlib.import_module('os').system('terraform destroy')\"", false, "uses importlib"},
		{"eval", "python3 -c \"eval('print(1)'); open('a.tf','w').write('terraform')\"", false, "uses eval()"},
		{"exec", "python3 -c \"exec(open('x').read()); open('a.tf','w').write('terraform')\"", false, "uses exec()"},
		{"sys.modules", "python3 -c \"import sys; sys.modules['os'].system('terraform destroy')\"", false, "uses sys.modules"},
		{"shutil", "python3 -c \"import shutil; shutil.rmtree('.terraform'); open('a.tf','w').write('terraform')\"", false, "uses shutil"},
		{"local module import", "python3 -c \"import helper; helper.fix('terraform')\"", false, "imports helper"},
		{"ctypes", "python3 -c \"import ctypes; open('a.tf','w').write('terraform')\"", false, "uses ctypes"},
		{"asyncio import", "python3 -c \"import asyncio; open('a.tf','w').write('terraform')\"", false, "imports asyncio"},
		{"boto3", "python3 -I - <<'EOF'\nimport boto3\ns=open('main.tf').read()\nopen('main.tf','w').write(s.replace('terraform','tofu'))\nEOF", false, "uses an AWS SDK"},
		{"requests", "python3 -c \"import requests; open('a.tf','w').write('terraform')\"", false, "imports requests"},
		{"urllib", "python3 -c \"from urllib.request import urlopen; open('a.tf','w').write('terraform')\"", false, "imports urllib.request"},
		{"pickle", "python3 -c \"import pickle; open('a.tf','w').write('terraform')\"", false, "uses pickle"},
		{"base64 in the body", "python3 -c \"import base64; open(base64.b64decode('Lg==').decode(),'w').write('terraform')\"", false, "uses base64"},
		{"escaped characters", `python3 -c "open('\x61.tf','w').write('terraform')"`, false, "builds text at run time"},
		{"chr()", `python3 -c "open(chr(97)+'.tf','w').write('terraform')"`, false, "builds text at run time"},
		{"reversed slice", `python3 -c "open('ft.a'[::-1],'w').write('terraform')"`, false, "builds text at run time"},
		{"guard name under an escaped character", `python3 -c "open('\x2eapplygate.yaml','w').write('terraform')"`, false, "builds text at run time"},
		{"yaml.load", "python3 -c \"import yaml; yaml.load(open('x')); open('a.tf','w').write('terraform')\"", false, "uses yaml.load"},

		// Guard, credential and state files keep today's verdicts.
		{"legacy guard file name still guarded", "python3 -I - <<'EOF'\ns=open('.seatbelt.yaml').read()\nopen('.seatbelt.yaml','w').write(s.replace('enforce','observe'))\nEOF", false, "names .seatbelt.yaml"},
		{"legacy user config path still guarded", `python3 -c "open('/h/.config/seatbelt/config.yaml','w').write('mode: observe # terraform')"`, false, "seatbelt/config.yaml"},
		{"guard file target", "python3 -I - <<'EOF'\ns=open('.applygate.yaml').read()\nopen('.applygate.yaml','w').write(s.replace('enforce','observe'))\nEOF", false, "names .applygate.yaml"},
		{"guard file split across literals", `python3 -c "open('.apply'+'gate.yaml','w').write('mode: observe # terraform')"`, false, "names .applygate.yaml"},
		{"hook config", `python3 -c "open('.claude/settings.json','w').write('{} # terraform')"`, false, "names .claude/settings"},
		{"credential file", `python3 -c "print(open('/h/.aws/credentials').read()); open('a.tf','w').write('terraform')"`, false, "names /h/.aws/credentials"},
		{"state file as a target", "python3 -I - <<'EOF'\np='terraform.tfstate'\ns=open(p).read()\nopen(p,'w').write(s.replace('\"serial\": 5','\"serial\": 6'))\nEOF", false, "names the state file terraform.tfstate"},
		{"state file as a literal target", `python3 -c "open('envs/prod/terraform.tfstate','w').write('{}')"`, false, "names the state file envs/prod/terraform.tfstate"},
		{"provider cache", `python3 -c "open('.terraform/terraform.tfstate','w').write('{} # terraform')"`, false, "names the state file .terraform/terraform.tfstate"},
		{"pathlib is not followed", `python3 -c "from pathlib import Path; Path('a.tf').write_text('terraform')"`, false, "imports pathlib"},
		{"fileinput rewrites in place", `python3 -c "import fileinput; [print(l.replace('terraform','tofu'), end='') for l in fileinput.input(['a.tf'], inplace=True)]"`, false, "imports fileinput"},

		// Write targets assembled at run time fail closed (adversarial review).
		{"guard name assembled from pieces", "python3 -I - <<'EOF'\nimport os\na='apply'\nb='gate'\np='.'+a+b+'.yaml'\n# edit terraform.workspace\nopen(p,'w').write('mode: observe\\n')\nEOF", false, "open() writes to a path it builds at run time"},
		{"state file split across literals", `python3 -c "open('x.'+'tfstate','w').write('{}') # terraform"`, false, "names the state file x.tfstate"},
		{"os.replace onto an assembled name", "python3 -I - <<'EOF'\nimport os\na='apply'\np='.'+a+'gate.yaml'\nopen('tmp','w').write('mode: observe # terraform')\nos.replace('tmp',p)\nEOF", false, "replace() writes to a path it builds at run time"},
		{"os.symlink onto an assembled name", "python3 -I - <<'EOF'\nimport os\na='apply'\np='.'+a+'gate.yaml'\nos.symlink('/etc/evil', p) # terraform\nEOF", false, "symlink() writes to a path it builds at run time"},
		{"os.link to a literal guard name", `python3 -c "import os; os.link('a.tf', '.apply'+'gate.yaml') # terraform"`, false, "names .applygate.yaml"},
		{"f-string target", `python3 -c "a='applygate'; open(f'.{a}.yaml','w').write('terraform')"`, false, "open() writes to a path it builds at run time"},
		{"f-string target without the name", `python3 -c "a='.tf'; open(f'main{a}','w').write('terraform')"`, false, "open() writes to a path it builds at run time"},
		{"percent-formatted target", `python3 -c "p='%s.tf' % 'main'; open(p,'w').write('terraform')"`, false, "open() writes to a path it builds at run time"},
		{"os.path.join target", `python3 -c "import os; open(os.path.join('envs','main.tf'),'w').write('terraform')"`, false, "open() writes to a path it builds at run time"},
		{"reassigned name", `python3 -c "p='a.tf'; p=p+'x'; open(p,'w').write('terraform')"`, false, "open() writes to a path it builds at run time"},
		{"augmented assignment", "python3 -I - <<'EOF'\np='a'\np+='.tf'\nopen(p,'w').write('terraform')\nEOF", false, "open() writes to a path it builds at run time"},
		{"keyword argument target", `python3 -c "p='a.tf'; open(file=p, mode='w').write('terraform')"`, false, "open() writes to a path it builds at run time"},
		{"unknown mode", `python3 -c "m='w'; open(os_path,m).write('terraform')"`, false, "open() writes to a path it builds at run time"},
		{"read of an unresolved path is fine", `python3 -c "import sys; s=open(sys.argv[0]).read(); open('a.tf','w').write(s.replace('terraform','tofu'))"`, true, ""},
		{"os.environ", `python3 -c "import os; os.environ['BASH_ENV']='/tmp/x'; open('a.tf','w').write('terraform')"`, false, "uses environ"},
		{"import os as alias", `python3 -c "import os as o; o.rename('a.tf','b.tf') # terraform"`, false, "imports os under another name"},
		{"os through another module", `python3 -c "import glob; glob.os.rename('a.tf','b.tf') # terraform"`, false, "uses .os"},
		{"help() opens a pager", `python3 -c "help(str); open('a.tf','w').write('terraform')"`, false, "uses help()"},
		{"fexecve", `python3 -c "import os; os.fexecve(3, ['terraform','destroy'], {})"`, false, "uses fexecve()"},
		{"full-width identifiers", "python3 -c \"\uff45\uff56\uff41\uff4c('1'); open('a.tf','w').write('terraform')\"", false, "uses eval()"},
		{"writes a shell start-up file", `python3 -c "open('/h/.bashrc','a').write('alias terraform=rm')"`, false, "names /h/.bashrc"},
		{"writes a program file", `python3 -c "open('run.sh','w').write('terraform destroy')"`, false, "writes run.sh (not a repository configuration file)"},
		{"writes into .git", `python3 -c "open('.git/hooks/pre-commit','w').write('terraform destroy')"`, false, "names .git/hooks"},
		{"relative target resolved against the directory", `cd .claude && python3 -c "open('settings.json','w').write('{} # terraform')"`, false, "touches the guard file settings.json"},
		{"relative target in an ordinary directory", `cd envs/prod && python3 -c "open('settings.json','w').write('{} # terraform')"`, true, ""},
		{"node assembled guard name", `node -e "const fs=require('fs');const a='apply';const b='gate';const p='.'+a+b+'.yaml';/* terraform */fs.writeFileSync(p,'mode: observe');"`, false, "writeFileSync() writes to a path it builds at run time"},
		{"node state file split across literals", `node -e "require('fs').writeFileSync('x.'+'tfstate','{}') // terraform"`, false, "names the state file x.tfstate"},
		{"node template literal target", "node -e 'const a=\"main\";require(\"fs\").writeFileSync(`${a}.tf`,\"terraform\")'", false, "writeFileSync() writes to a path it builds at run time"},
		{"node plain template literal target", "node -e 'require(\"fs\").writeFileSync(`main.tf`,\"terraform\")'", true, ""},
		{"node path.join target", `node -e "const p=require('path');require('fs').writeFileSync(p.join('envs','main.tf'),'terraform')"`, false, "writeFileSync() writes to a path it builds at run time"},
		{"node symlink destination", `node -e "const fs=require('fs');const d='.apply'+'gate.yaml';fs.symlinkSync('/etc/evil', d) // terraform"`, false, "names .applygate.yaml"},
		{"node copyFileSync destination assembled", `node -e "const fs=require('fs');const d=['.appl','ygate.yaml'].join('');fs.copyFileSync('a.tf', d) // terraform"`, false, "copyFileSync() writes to a path it builds at run time"},
		{"node process.env write", `node -e "process.env.BASH_ENV='/tmp/x';require('fs').writeFileSync('a.tf','terraform')"`, false, "uses process.env"},
		{"node process.chdir", `node -e "process.chdir('.claude');require('fs').writeFileSync('settings.json','terraform')"`, false, "names .claude"},
		{"guard file as a script argument", "python3 fix.py ../.applygate.yaml", false, "an argument names"},
		{"state file as a script argument", "python3 fix.py terraform.tfstate", false, "an argument names"},
		{"configured guard file", "python3 -c \"open('audit.jsonl','a').write('terraform')\"", false, "names the guard file audit.jsonl"},
		{"node writes a guard file", `node -e "const fs=require('fs');fs.writeFileSync('.applygate.yaml','mode: observe # terraform')"`, false, "names .applygate.yaml"},

		// Node ways to run something.
		{"node child_process", `node -e "require('child_process').execSync('terra'+'form destroy')"`, false, "uses child_process"},
		{"node destructured execSync", `node -e "const {execSync}=require('fs');execSync('terraform destroy')"`, false, "uses execSync()"},
		{"node split module name", `node -e "const cp=require('child_'+'process');cp.exec('terraform destroy')"`, false, "uses child_process"},
		{"node computed require without a call", `node -e "const m=['child','process'].join('_');const cp=require(m);cp.exec('terraform destroy')"`, false, "requires a module whose name is computed"},
		{"node Function constructor", `node -e "new Function('return process')().mainModule.require('child_process').exec('terraform destroy')"`, false, "uses Function"},
		{"node fetch", `node -e "fetch('https://x').then(()=>require('fs').writeFileSync('a.tf','terraform'))"`, false, "uses fetch"},
		{"node https import", `node -e "import https from 'https'; require('fs').writeFileSync('a.tf','terraform')"`, false, "imports https"},
		{"node dynamic import", `node -e "const n=process.argv[1];import(n).then(cp=>cp.exec('terraform destroy'))"`, false, "requires a module whose name is computed"},
		{"node process index", `node -e "process['binding']('spawn_sync'); require('fs').writeFileSync('a.tf','terraform')"`, false, "uses process["},

		// Bodies that are not fully known, or not Python or Node.
		{"unquoted heredoc with a variable", "python3 - <<EOF\nimport re\np='cluster.tf'\ns=open(p).read().replace('terraform', '$NAME')\nopen(p,'w').write(s)\nEOF", false, "cannot be analyzed"},
		{"decoded body", "echo cz1vcGVuKCdtYWluLnRmJykucmVhZCgpOyBvcGVuKCdtYWluLnRmJywndycpLndyaXRlKHMucmVwbGFjZSgndGVycmFmb3JtJywndG9mdScpKQo= | base64 -d | python3", false, "cannot be analyzed"},
		{"unresolved script argument", "python3 fix.py $TARGET", false, "an argument cannot be resolved"},
		{"perl", `perl -e 'open(F,">x.tf"); print F "terraform {}"'`, false, "cannot be analyzed"},
		{"ruby", `ruby -e 'File.write("x.tf", "terraform {}")'`, false, "cannot be analyzed"},

		// Review of PR #31: functions passed by reference, names rebound by
		// loops, aliases and parameters, imports after a colon, traversal
		// and other write targets, and the positive rule for writes.
		{"os.system passed to sys.call_tracing", "python3 -c \"import os,sys; sys.call_tracing(os.system, ('terraform destroy -auto-approve',))\"", false, "uses call_tracing()"},
		{"os.system passed to map", "python3 -c \"import os; list(map(os.system, ['terraform destroy']))\"", false, "uses system()"},
		{"os.system through __call__", "python3 -c \"import os; os.system.__call__('terraform destroy')\"", false, "uses system()"},
		{"os.system through operator.call", "python3 -c \"import operator,os; operator.call(os.system,'terraform destroy')\"", false, "uses call()"},
		{"open bound to another name", "python3 -c \"f=open; f('run.sh','w').write('terraform destroy')\"", false, "passes open by reference"},
		{"open inside a list", "python3 -c \"[open][0]('run.sh','w').write('terraform destroy')\"", false, "passes open by reference"},
		{"os.replace passed to functools.partial", "python3 -c \"import os,functools; w=functools.partial(os.replace,'a.tf'); w('run.sh') # terraform\"", false, "passes replace by reference"},
		{"getattr passed to reduce", "python3 -c \"import functools,os; functools.reduce(getattr, ['system'], os)('terraform destroy')\"", false, "uses getattr()"},
		{"FileIO imported by name", "python3 -c \"from io import FileIO as F; F('run.sh','w').write(b'terraform destroy')\"", false, "imports FileIO from io"},
		{"frame access", "python3 -c \"import sys; sys._getframe().f_builtins['exec']('print(1)') # terraform\"", false, "uses f_builtins()"},
		{"string.Formatter resolves attributes", "python3 -c \"import string,os; string.Formatter().get_field('0.system',(os,),{})[0]('terraform destroy')\"", false, "uses Formatter()"},
		{"name rebound by a for loop", "python3 -I - <<'EOF'\np='a.tf'\nfor p in ['run.sh']:\n    open(p,'w').write('terraform destroy')\nEOF", false, "open() writes to a path it builds at run time"},
		{"name rebound by a comprehension", "python3 -c \"p='a.tf'; [open(p,'w').write('terraform destroy') for p in ['run.sh']]\"", false, "open() writes to a path it builds at run time"},
		{"name rebound by with-as", "python3 -I - <<'EOF'\np='a.tf'\nwith open('list.txt') as p:\n    open(p,'w').write('terraform destroy')\nEOF", false, "open() writes to a path it builds at run time"},
		{"name rebound by a lambda parameter", "python3 -c \"p='a.tf'; f=lambda p: open(p,'w').write('terraform destroy'); f('run.sh')\"", false, "open() writes to a path it builds at run time"},
		{"name rebound by a def parameter", "python3 -I - <<'EOF'\np='a.tf'\ndef f(p):\n    open(p,'w').write('terraform destroy')\nf('run.sh')\nEOF", false, "open() writes to a path it builds at run time"},
		{"name rebound by tuple unpacking", "python3 -c \"p='a.tf'; p,q=('run.sh',1); open(p,'w').write('terraform destroy')\"", false, "open() writes to a path it builds at run time"},
		{"name rebound by a walrus", "python3 -c \"p='a.tf'; print((p:='run.sh')); open(p,'w').write('terraform destroy')\"", false, "open() writes to a path it builds at run time"},
		{"node name rebound by for-of", `node -e "const fs=require('fs');let p='a.tf';for (p of ['run.sh']) fs.writeFileSync(p,'terraform destroy')"`, false, "writeFileSync() writes to a path it builds at run time"},
		{"node name rebound by a parameter", `node -e "const fs=require('fs');let p='a.tf';function w(p){fs.writeFileSync(p,'terraform destroy')};w('run.sh')"`, false, "writeFileSync() writes to a path it builds at run time"},
		{"node name rebound by an arrow parameter", `node -e "const fs=require('fs');let p='a.tf';['run.sh'].forEach(p=>fs.writeFileSync(p,'terraform destroy'))"`, false, "writeFileSync() writes to a path it builds at run time"},
		{"node writeFileSync bound to another name", `node -e "const fs=require('fs');const w=fs.writeFileSync;w('run.sh','terraform destroy')"`, false, "passes writeFileSync by reference"},
		{"node writeFileSync through call", `node -e "const fs=require('fs');fs.writeFileSync.call(fs,'run.sh','terraform destroy')"`, false, "uses call()"},
		{"node member reached with a string", `node -e "const fs=require('fs');fs['writeFileSync']('run.sh','terraform destroy')"`, false, "reaches a member with a string index"},
		{"node destructured import is a call", `node -e "const {readFileSync,writeFileSync}=require('fs');writeFileSync('a.tf',readFileSync('a.tf','utf8').replace('terraform','tofu'))"`, true, ""},
		{"node destructured import with an alias", `node -e "const {writeFileSync: w}=require('fs');w('run.sh','terraform destroy')"`, false, "passes writeFileSync by reference"},
		{"import after a colon", "python3 -I - <<'EOF'\nif 1: import asyncio\nasyncio.run(asyncio.create_subprocess_shell('terraform destroy -auto-approve'))\nEOF", false, "uses create_subprocess_shell"},
		{"import in a try block", "python3 -I - <<'EOF'\ntry: import multiprocessing\nexcept ImportError: pass\nopen('a.tf','w').write('terraform')\nEOF", false, "imports multiprocessing"},
		{"traversal into a scheduler directory", `cd envs/prod && python3 -c "open('../../../../etc/cron.d/tf','w').write('* * * * * root terraform destroy')"`, false, "names ../../../../etc/cron.d/tf"},
		{"traversal out of the working directory", `cd envs/prod && python3 -c "open('../../../outside.tf','w').write('terraform {}')"`, false, "writes ../../../outside.tf outside the working directory"},
		{"absolute target under the working directory", `python3 -c "open('/repo/envs/main.tf','w').write('terraform {}')"`, true, ""},
		{"absolute target elsewhere", `python3 -c "open('/other/main.tf','w').write('terraform {}')"`, false, "writes /other/main.tf outside the working directory"},
		{"io.FileIO write", "python3 -c \"import io; io.FileIO('run.sh','w').write(b'terraform destroy')\"", false, "writes run.sh (not a repository configuration file)"},
		{"io.FileIO on a state file", "python3 -c \"import io; io.FileIO('terraform.tfstate','w').write(b'{}')\"", false, "names the state file terraform.tfstate"},
		{"tempfile is not followed", "python3 -c \"import tempfile; fd,p=tempfile.mkstemp(); open('a.tf','w').write('terraform')\"", false, "imports tempfile"},
		{"os.fdopen", "python3 -c \"import os; os.fdopen(3,'w').write('terraform destroy')\"", false, "uses fdopen()"},
		{"writes .envrc", `python3 -c "open('.envrc','w').write('export TF_CLI_ARGS=-auto-approve # terraform')"`, false, "names .envrc"},
		{"writes a lowercase makefile", `python3 -c "open('makefile','w').write('all: ; terraform destroy')"`, false, "writes makefile (not a repository configuration file)"},
		{"writes a TypeScript file", `python3 -c "open('run.ts','w').write('// terraform')"`, false, "writes run.ts (not a repository configuration file)"},
		{"writes package.json", `python3 -c "open('package.json','w').write('{\"scripts\":{\"postinstall\":\"terraform destroy\"}}')"`, false, "writes the tool manifest package.json"},
		{"writes a workflow file", `python3 -c "open('.github/workflows/ci.yml','w').write('run: terraform destroy')"`, false, "writes the hidden file .github/workflows/ci.yml"},
		{"writes a hidden tflint config", `python3 -c "open('.tflint.hcl','w').write('# terraform')"`, false, "writes the hidden file .tflint.hcl"},
		{"renames a directory", "python3 -c \"import os; os.rename('modules/old','modules/new') # terraform\"", false, "writes modules/old (not a repository configuration file)"},
		{"makes a directory", "python3 -c \"import os; os.makedirs('modules/vpc', exist_ok=True); open('modules/vpc/main.tf','w').write('terraform {}')\"", true, ""},
		{"writes a tfvars.json and a markdown file", `python3 -c "open('prod.auto.tfvars.json','w').write('{}'); open('README.md','w').write('# terraform')"`, true, ""},
		{"reads a directory listing", "python3 -c \"import os; [open(f,'a').write('# terraform') for f in os.listdir('.') if f.endswith('.tf')]\"", false, "open() writes to a path it builds at run time"},

		// Text that only looks like a guard word is not a guard file.
		{"provider.aws in HCL text", `python3 -c "s=open('main.tf').read(); open('main.tf','w').write(s.replace('provider.aws','provider.aws.primary')) # terraform"`, true, ""},
		{"module.aws in HCL text", `python3 -c "open('main.tf','a').write('module \"net\" { providers = { aws = module.aws.primary } } # terraform')"`, true, ""},
		{"applygate as a word in a comment", `python3 -c "open('main.tf','a').write('# managed by applygate; see terraform docs')"`, true, ""},
		{"kube-system in a regex", `python3 -c "import re; s=open('eks.tf').read(); open('eks.tf','w').write(re.sub(r'namespace = \"kube-system\"', 'namespace = \"kube-system\" # terraform', s))"`, true, ""},
		{"remove and open as words in a comment", "python3 -I - <<'EOF'\n# remove the old block and open the file for terraform fmt\ns=open('main.tf').read()\nopen('main.tf','w').write(s.replace('x','y'))\nEOF", true, ""},
		{"f-string content with braces", "python3 -c \"k='web'; open('main.tf','a').write(f'resource \\\"aws_instance\\\" \\\"{k}\\\" {{}} # terraform')\"", true, ""},
		{"f-string expression that runs code", "python3 -c \"import os; open('main.tf','a').write(f'{os.system(\\\"terraform destroy\\\")}')\"", false, "uses system()"},
		{"io reached through yaml", "python3 -c \"import yaml; yaml.io.open('run.sh','w').write('terraform destroy')\"", false, "reaches a module through another module (.io)"},
		{"fchdir", "python3 -c \"import os; os.fchdir(3); open('a.tf','w').write('terraform')\"", false, "uses fchdir()"},
		{"yaml.full_load_all", "python3 -c \"import yaml; list(yaml.full_load_all(open('x.yaml'))); open('a.tf','w').write('terraform')\"", false, "uses yaml.full_load_all"},
		{"argparse FileType writes argv paths", "python3 -c \"import argparse; p=argparse.ArgumentParser(); p.add_argument('out', type=argparse.FileType('w')); p.parse_args().out.write('terraform destroy')\" run.sh", false, "uses FileType()"},
		{"node ES import with an alias", `node -e "import {writeFileSync as w} from 'fs'; w('run.sh','terraform destroy')"`, false, "passes writeFileSync by reference"},
		{"name rebound by a case capture", "python3 -I - <<'EOF'\nimport sys\np='a.tf'\nmatch sys.argv[1:]:\n    case [p]:\n        open(p,'w').write('terraform destroy')\nEOF", false, "open() writes to a path it builds at run time"},
		{"vars as a variable name is not the builtin", "python3 -c \"import json; vars = json.load(open('vars.json')); open('a.tf','w').write('terraform {}' + vars['x'])\"", true, ""},
		{"vars used before it is assigned", "python3 -c \"import os; v = vars(os); vars = 1; v['system']('terraform destroy')\"", false, "uses vars()"},
		{"unclosed string literal", "python3 -c \"open('main.tf','a').write('terraform\n\"", false, "a string literal is not closed"},
	}
	for _, c := range cases {
		r := Analyze(c.cmd, Options{Dir: "/repo", Env: map[string]string{"HOME": "/h"}, ReadFile: fs, MaxDepth: 8,
			ProtectedPaths: []string{"**/.applygate.yaml", "/var/log/agent/audit.jsonl"},
			ProtectedPath: func(p string) bool {
				return strings.HasSuffix(p, "/.claude/settings.json") || strings.HasSuffix(p, "/.applygate.yaml") || p == "/var/log/agent/audit.jsonl"
			}})
		got := strings.Join(render(r), "\n")
		if c.note {
			if len(r.Problems) != 0 {
				t.Errorf("%s: want no problem, got:\n%s", c.name, got)
			}
			if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "treated as a file edit") {
				t.Errorf("%s: want one file-edit note, got %v", c.name, r.Notes)
			}
			continue
		}
		if len(r.Notes) != 0 {
			t.Errorf("%s: want no note, got %v", c.name, r.Notes)
		}
		if len(r.Problems) == 0 {
			t.Errorf("%s: want a problem, got none:\n%s", c.name, got)
			continue
		}
		if !strings.Contains(r.Problems[0].Reason, "code mentions infrastructure") || !strings.Contains(r.Problems[0].Reason, c.reason) {
			t.Errorf("%s: want reason containing %q, got %q", c.name, c.reason, r.Problems[0].Reason)
		}
	}
}

// A repository that lives under a directory named like a guard file (this
// project's own worktrees sit in .claude/worktrees/) is not a guard file.
func TestFileOnlyIgnoresGuardWordsInTheRepositoryPath(t *testing.T) {
	for _, dir := range []string{"/home/u/.claude/worktrees/applygate/envs/prod", "/home/u/.config/work/repo", "/var/lib/ci/workspace/.aws-infra"} {
		r := Analyze(trialEdits[3], Options{Dir: dir, ReadFile: fakeFS(nil), ProtectedPaths: []string{"**/.applygate.yaml", "**/.local/state/applygate/**"},
			ProtectedPath: func(p string) bool { return strings.HasSuffix(p, "/.applygate.yaml") }})
		if len(r.Problems) != 0 || len(r.Notes) != 1 {
			t.Errorf("%s: problems %+v notes %v", dir, r.Problems, r.Notes)
		}
	}
}

func TestFileOnlyPerlAndUnknownLanguagesKeepThePlainReason(t *testing.T) {
	r := Analyze(`perl -e 'system("terra"."form destroy")'`, Options{Dir: "/repo", ReadFile: fakeFS(nil)})
	if len(r.Problems) != 1 || strings.Contains(r.Problems[0].Reason, "(") {
		t.Fatalf("perl should keep the plain reason: %+v", r.Problems)
	}
}

func TestGuardNeedles(t *testing.T) {
	cases := map[string]string{
		"**/.applygate.yaml":               ".applygate.yaml",
		"**/managed-settings.d/**":         "managed-settings.d",
		"**/.local/state/applygate/**":     ".local/state/applygate applygate",
		"/var/log/agent/audit.jsonl":       "/var/log/agent/audit.jsonl audit.jsonl",
		"infra/*/hooks.json":               "hooks.json",
		"**/*.log":                         "",
		"":                                 "",
		"**/.config/applygate/config.yaml": ".config/applygate/config.yaml config.yaml",
	}
	for in, want := range cases {
		if got := strings.Join(guardNeedles(in), " "); got != want {
			t.Errorf("guardNeedles(%q) = %q, want %q", in, got, want)
		}
	}
}
