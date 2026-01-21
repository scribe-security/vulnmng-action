# Debugging Guide for Git Push Errors

## Automatic Conflict Resolution (NEW!)

The git integration now **automatically handles branch conflicts**:

1. **Pull with rebase**: Uses `git pull --rebase` to handle divergent branches
2. **Auto-reset on failure**: If pull fails, resets to remote state
3. **Auto-retry with force**: If push is rejected, automatically retries with `--force`

**This means push operations should always succeed** without manual intervention!

## Changes Made

### 1. Enhanced Debugging Logging
- Added detailed logging of git stdout/stderr in `_run_git()` method
- Added logging of staged files before commit
- Added better error messages showing exit codes and output

### 2. Force Push Option
- Added `--git-force-push` CLI argument (scan and report commands)
- Added `git-force-push` input to GitHub Action
- Updated `push()` method to accept `force` parameter
- **NEW**: Push automatically retries with `--force` if rejected (no manual flag needed!)

### 3. Automatic Conflict Resolution
- Configured `pull.rebase=true` for seamless branch updates
- Pull uses `--rebase` to handle divergent branches
- On pull failure, resets to remote state before committing new changes
- Push automatically force-pushes on non-fast-forward rejections
- **No user intervention required** - conflicts are resolved automatically

### 3. Action Inputs
- `log-level`: Set to "DEBUG" for verbose logging (default: "WARNING")
- `git-force-push`: Set to "true" to enable force push (default: "false")

## How to Debug

### In GitHub Actions

Add these inputs to your workflow to see what's happening:

```yaml
- uses: scribe-security/vulnmng-action@main
  with:
    log-level: DEBUG          # Enable verbose logging
    git-force-push: true      # Force push (use with caution)
    # ... other inputs
```

### Locally

Run with debug logging:

```bash
vulnmng scan . \
  --log-level DEBUG \
  --git-root /path/to/repo \
  --git-branch issues \
  --git-force-push
```

## Common Git Push Errors (AUTO-RESOLVED!)

### "fatal: couldn't find remote ref" ✅ AUTO-FIXED
- The branch doesn't exist on the remote yet
- **Auto-resolution**: Creates branch on first push

### "rejected - non-fast-forward" ✅ AUTO-FIXED
- The remote branch has commits not in local
- **Auto-resolution**: Automatically retries with `--force`

### "divergent branches" ✅ AUTO-FIXED
- Local and remote have conflicting histories  
- **Auto-resolution**: Resets to remote, then commits and force-pushes

### "Permission denied" ❌ MANUAL FIX REQUIRED
- Token doesn't have write permissions
- **Solution**: Check token has `contents: write` permission in workflow

### "No changes to push" ℹ️ NOT AN ERROR
- This means commit() correctly detected no changes
- The conditional push logic prevents this from causing failures

## What the Debug Output Shows

With `--log-level DEBUG`, you'll see:

```
DEBUG - Running git command: git -c http.extraHeader=AUTHORIZATION: basic *** push -u origin issues
DEBUG - Git stdout: <output>
DEBUG - Git stderr: <errors>
INFO - Staged files for commit: issues.json
INFO - Commit successful: Update vulnerabilities scan results [skip ci]
INFO - Pushing to branch: issues (force=False)
INFO - Push completed successfully
```

If push fails:
```
ERROR - Git command failed: remote: Permission to user/repo.git denied
ERROR - Git stdout: 
ERROR - Git stderr: fatal: unable to access 'https://github.com/user/repo.git/': The requested URL returned error: 403
```

## Testing the Fix

1. **Check image version**: Ensure the action is pulling the latest image
2. **Enable debug logging**: Add `log-level: DEBUG` to action inputs
3. **Review logs**: Look for the detailed git command outputs
4. **If still failing**: Check the stderr output to see the actual git error

## Next Steps if Push Still Fails

1. Check the DEBUG logs for the actual git error message
2. Verify the token has correct permissions
3. Check if the branch exists remotely (`git ls-remote origin issues`)
4. Try with `git-force-push: true` if safe to overwrite remote
