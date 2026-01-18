import subprocess
import logging
import os
import base64
from typing import Optional

logger = logging.getLogger(__name__)

class GitIntegration:
    def __init__(self, repo_path: str = ".", branch: Optional[str] = None, token: Optional[str] = None):
        self.repo_path = repo_path
        self.branch = branch
        self.token = token

    def _run_git(self, args: list, raise_error: bool = False) -> bool:
        try:
            cmd = ["git"]
            if self.token:
                # Format: Authorization: Basic base64(x-access-token:TOKEN)
                auth_str = f"x-access-token:{self.token}"
                encoded_auth = base64.b64encode(auth_str.encode()).decode()
                auth_header = f"AUTHORIZATION: basic {encoded_auth}"
                cmd.extend(["-c", f"http.extraHeader={auth_header}"])
            
            cmd.extend(args)
            # Log the command but mask the token in logs if possible
            # (Though GitHub Actions usually masks the raw token anyway)
            logger.debug(f"Running git command: {' '.join(['***' if 'AUTHORIZATION' in a else a for a in cmd])}")
            
            result = subprocess.run(
                cmd, 
                cwd=self.repo_path, 
                capture_output=True, 
                text=True, 
                check=True
            )
            if result.stdout:
                logger.debug(f"Git stdout: {result.stdout}")
            if result.stderr:
                logger.debug(f"Git stderr: {result.stderr}")
            return True
        except subprocess.CalledProcessError as e:
            # Use DEBUG level since many "failures" are expected (e.g., checking if config exists)
            logger.debug(f"Git command failed with exit code {e.returncode}")
            logger.debug(f"Git stdout: {e.stdout}")
            logger.debug(f"Git stderr: {e.stderr}")
            if raise_error:
                logger.error(f"Git command failed: {e.stderr}")
                raise
            return False

    def ensure_safe_directory(self):
        """Adds repo_path to git's safe.directory if not already present."""
        abs_path = os.path.abspath(self.repo_path)
        logger.debug(f"Ensuring {abs_path} is marked as a safe directory")
        # Use subprocess directly to avoid cwd issues before it's marked safe
        try:
            subprocess.run(
                ["git", "config", "--global", "--add", "safe.directory", abs_path],
                check=True,
                capture_output=True
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to set safe.directory: {e.stderr}")

    def ensure_identity(self):
        """Sets a default git identity if none is configured."""
        logger.debug("Ensuring git identity is configured")
        # Check if user.email is set
        if not self._run_git(["config", "--get", "user.email"]):
            logger.debug("Setting default git user.email")
            self._run_git(["config", "--global", "user.email", "actions@github.com"])
        
        # Check if user.name is set
        if not self._run_git(["config", "--get", "user.name"]):
            logger.debug("Setting default git user.name")
            self._run_git(["config", "--global", "user.name", "GitHub Actions"])

    def is_repo(self) -> bool:
        # We try a simple command first, if it fails with dubious ownership, we fix it
        if not self._run_git(["rev-parse", "--is-inside-work-tree"]):
            # Check if it was a dubious ownership error
            # (Note: we don't have the e.stderr here easily because _run_git catches it)
            # Let's just always ensure safe directory if is_repo is called? 
            # Or better, just call it explicitly in CLI.
            return False
        return True

    def checkout_branch(self):
        if not self.branch:
            return
        
        # Try checking out the branch directly.
        # If it exists locally OR on origin (modern git will auto-track), this works.
        logger.info(f"Attempting to checkout branch: {self.branch}")
        if self._run_git(["checkout", self.branch]):
            return
            
        # If it failed, it might truly be a new branch
        logger.debug(f"Branch {self.branch} not found locally or on origin. Creating it.")
        if not self._run_git(["checkout", "-b", self.branch]):
            logger.error(f"Failed to create branch {self.branch}")
            # We don't raise here yet, but we should probably inform the CLI

    def pull(self):
        """Pull latest changes from remote branch.
        
        Uses rebase strategy to handle divergent branches automatically.
        If pull fails, resets to remote to ensure clean state.
        """
        logger.debug(f"Attempting to sync with remote branch: {self.branch}")
        
        # Configure pull strategy to use rebase (good for automated workflows)
        self._run_git(["config", "pull.rebase", "true"], raise_error=False)
        
        # First try to fetch to get latest refs
        try:
            self._run_git(["fetch", "origin", self.branch], raise_error=False)
            logger.debug(f"Fetched latest refs for {self.branch}")
        except Exception as e:
            logger.debug(f"Fetch failed (may be new branch): {e}")
            # Branch doesn't exist remotely yet - nothing to pull
            logger.info(f"Branch {self.branch} has no remote yet (will be created on push)")
            return
        
        # Try to pull with rebase
        try:
            self._run_git(["pull", "--rebase", "origin", self.branch], raise_error=True)
            logger.info(f"Successfully synced with remote {self.branch}")
            return
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.lower() if e.stderr else ""
            
            # Branch doesn't exist remotely
            if any(phrase in stderr for phrase in [
                "couldn't find remote ref",
                "does not exist"
            ]):
                logger.info(f"Branch {self.branch} has no remote yet (will be created on push)")
                return
            
            # Divergent branches or rebase conflicts - reset to remote
            logger.warning(f"Pull failed, resetting to remote state: {e.stderr}")
            try:
                # Reset to remote branch (discard local changes in favor of remote)
                self._run_git(["reset", "--hard", f"origin/{self.branch}"], raise_error=True)
                logger.info(f"Reset local branch to match origin/{self.branch}")
            except subprocess.CalledProcessError:
                # Even reset failed - just continue, force push will handle it
                logger.warning("Could not reset to remote, will use force push")

    def add(self, file_path: str):
        self._run_git(["add", file_path])

    def commit(self, message: str) -> bool:
        """Commit staged changes if any exist.
        
        Returns:
            bool: True if a commit was made, False if there were no changes
        """
        logger.debug(f"Attempting to commit with message: {message}")
        # Check if there are staged changes
        try:
            subprocess.run(
                ["git", "diff", "--staged", "--quiet"],
                cwd=self.repo_path,
                check=True,
                capture_output=True
            )
            # If check=True succeeds, there are NO changes (exit code 0)
            logger.info("No changes to commit")
            return False
        except subprocess.CalledProcessError:
            # Exit code 1 means there ARE changes, proceed with commit
            # Log what files are staged
            try:
                status_result = subprocess.run(
                    ["git", "diff", "--staged", "--name-only"],
                    cwd=self.repo_path,
                    capture_output=True,
                    text=True
                )
                logger.info(f"Staged files for commit: {status_result.stdout.strip()}")
            except Exception:
                pass
        
        self._run_git(["commit", "-m", message])
        logger.info(f"Commit successful: {message}")
        return True

    def push(self, force=False):
        """Push commits to remote repository.
        
        Automatically retries with force push if normal push is rejected.
        
        Args:
            force: If True, use --force flag immediately
        """
        logger.info(f"Pushing to branch: {self.branch} (force={force})")
        args = ["push"]
        if force:
            args.append("--force")
        if self.branch:
             # Set upstream if needed
             args.extend(["-u", "origin", self.branch])
        
        try:
            # _run_git now handles injecting the token headers
            self._run_git(args, raise_error=True)
            logger.info("Push completed successfully")
        except subprocess.CalledProcessError as e:
            if not force and e.returncode == 1:
                stderr = e.stderr.lower() if e.stderr else ""
                # Check if it's a non-fast-forward error
                if "non-fast-forward" in stderr or "rejected" in stderr:
                    logger.warning("Push rejected (non-fast-forward), retrying with --force")
                    # Retry with force
                    args_force = ["push", "--force", "-u", "origin", self.branch]
                    self._run_git(args_force, raise_error=True)
                    logger.info("Force push completed successfully")
                else:
                    # Different error, re-raise
                    raise
            else:
                # Already tried force or different error code
                raise
