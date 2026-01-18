# Debugging Guide for Git Push Errors

## Changes Made

### 1. Enhanced Debugging Logging
- Added detailed logging of git stdout/stderr in `_run_git()` method
- Added logging of staged files before commit
- Added better error messages showing exit codes and output

### 2. Force Push Option
- Added `--git-force-push` CLI argument (scan and report commands)
- Added `git-force-push` input to GitHub Action
- Updated `push()` method to accept `force` parameter

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

## Common Git Push Errors

### "fatal: couldn't find remote ref"
- The branch doesn't exist on the remote yet
- Solution: Use `--git-force-push` or create the branch manually first

### "rejected - non-fast-forward"
- The remote branch has commits not in local
- Solution: Use `--git-force-push` (caution: this will overwrite remote)

### "Permission denied"
- Token doesn't have write permissions
- Solution: Check token has `contents: write` permission in workflow

### "No changes to push"
- This is not an error - means commit() correctly detected no changes
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
