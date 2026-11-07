package shell

import "testing"

func TestGitAllowList(t *testing.T) {
	plain := []string{
		"git status", "git status --short", "git status -sb", "git status --porcelain=v2 -uno", "git diff", "git diff --stat HEAD~1", "git diff --cached -- a.tf",
		"git diff -U5 main...HEAD", "git diff --check", "git diff --name-only HEAD", "git log", "git log --oneline -5", "git log -3 --format='%h %s' -- a", "git log --all --oneline -i --grep='x'",
		"git log -p -S foo", "git log -n 5", "git log --author=me --since=2.weeks", "git show HEAD:a.tf", "git show --stat HEAD", "git add .", "git add -A", "git add a b", "git add -u -n",
		"git commit -m msg", "git commit -am 'msg'", "git commit --amend --no-edit", "git commit -m msg --no-verify", "git commit -F msg.txt",
		"git checkout -b feat", "git checkout main", "git checkout -- a.tf", "git switch -c x", "git restore --staged a", "git restore -s HEAD~1 a", "git reset HEAD a", "git reset --soft HEAD~1",
		"git stash", "git stash pop", "git stash push -m x -- a", "git stash list", "git branch", "git branch -a -v", "git branch feat", "git tag v1", "git tag -a v1 -m x", "git tag -l 'v*'",
		"git fetch origin", "git fetch --all --prune", "git pull --rebase origin main", "git merge --no-ff feat", "git merge -s ours x", "git rebase main", "git rebase --continue", "git cherry-pick -x abc",
		"git rev-parse --show-toplevel", "git rev-parse --abbrev-ref HEAD", "git rev-list --count HEAD", "git ls-files '*.tf'", "git ls-tree -r HEAD", "git blame -L 1,5 a", "git describe --tags --always",
		"git grep -n foo -- .", "git grep -i -e a -e b", "git shortlog -sn", "git reflog", "git ls-remote --tags https://github.com/a/b", "git cat-file -p HEAD", "git merge-base HEAD main",
		"git for-each-ref --format='%(refname)' refs/heads", "git symbolic-ref --short HEAD", "git show-ref --heads", "git check-ignore -v a", "git version", "git --version", "git remote -v", "git remote show origin",
		"git config --get user.name", "git config --list", "git config user.name x", "git mv a b", "git rm --cached a", "git clean -n", "git clean -fd", "git worktree list", "git -C sub status", "git --no-pager log",
		"git archive --format=tar HEAD", "git format-patch --stdout HEAD~1", "git bundle verify x", "git apply --check p.diff", "git init", "git clone https://github.com/a/b", "git count-objects -v",
	}
	for _, c := range plain {
		if ok, why := PlainShape(c, analyze(c, "/r")); !ok {
			t.Errorf("%q should be plain: %s", c, why)
		}
	}
	notPlain := []string{
		"git log --output=x", "git diff --output=x", "git diff --ext-diff", "git diff --textconv", "git show --textconv HEAD:a", "git log --ext-diff", "git grep -O sh foo", "git grep --open-files-in-pager=sh foo",
		"git rebase -x 'sh' main", "git rebase --exec sh main", "git rebase -i main", "git commit -S -m x", "git commit -e", "git commit --edit", "git commit -c HEAD", "git archive -o out.tar HEAD", "git archive --remote=x HEAD",
		"git archive --exec=sh HEAD", "git format-patch -o out HEAD~1", "git format-patch HEAD~1", "git fetch --upload-pack=sh origin", "git clone -u sh x", "git clone -c core.fsmonitor=sh x", "git clone --template=t x",
		"git ls-remote --upload-pack=sh origin", "git pull -s evil x", "git merge --strategy=evil x", "git push", "git push origin main", "git log --abbre", "git log --out=x", "git status $X", "git log $X",
		"git -c core.pager=sh log", "git -p log", "git --git-dir=x log", "git --exec-path=x log", "git difftool", "git mergetool", "git filter-branch", "git submodule foreach sh", "git bisect run sh", "git gc", "git update-ref x y",
		"git branch -D x", "git branch -m a b", "git branch --set-upstream-to=o/m", "git symbolic-ref HEAD refs/heads/x", "git reflog expire --all", "git log --help", "git help log -w", "git notes add -m x", "git bundle create f HEAD",
		"git cat-file --textconv HEAD:a", "git checkout --upload-pack=x", "git add -e", "git add -p", "git config -e", "git remote add x https://a/b", "git worktree add --help x", "git alias",
	}
	for _, c := range notPlain {
		if ok, _ := PlainShape(c, analyze(c, "/r")); ok {
			t.Errorf("%q should not be plain", c)
		}
	}
}
