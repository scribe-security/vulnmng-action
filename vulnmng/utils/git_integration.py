import subprocess
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

class GitIntegration:
    def __init__(self, repo_path: str = ".", branch: Optional[str] = None):
        self.repo_path = repo_path
        self.branch = branch

    def _run_git(self, args: list) -> bool:
        try:
            cmd = ["git"] + args
            logger.info(f"Running git command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd, 
                cwd=self.repo_path, 
                capture_output=True, 
                text=True, 
                check=True
            )
            if result.stdout:
                logger.debug(result.stdout)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Git command failed: {e.stderr}")
            return False

    def is_repo(self) -> bool:
        return self._run_git(["rev-parse", "--is-inside-work-tree"])

    def checkout_branch(self):
        if not self.branch:
            return
        
        # Check if branch exists locally using git branch --list
        try:
            result = subprocess.run(
                ["git", "branch", "--list", self.branch],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            branch_exists = bool(result.stdout.strip())
        except subprocess.CalledProcessError:
            branch_exists = False
        
        if branch_exists:
            # Branch exists, just checkout
            logger.info(f"Checking out existing branch {self.branch}")
            self._run_git(["checkout", self.branch])
        else:
            # Branch doesn't exist, create it
            logger.info(f"Creating new branch {self.branch}")
            self._run_git(["checkout", "-b", self.branch])

    def pull(self):
        # Try to pull, but don't fail if there's no upstream (new branch)
        try:
            result = subprocess.run(
                ["git", "pull"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            if result.stdout:
                logger.debug(result.stdout)
        except subprocess.CalledProcessError as e:
            # If the error is about no upstream, that's fine for a new branch
            if "no tracking information" in e.stderr or "There is no tracking information" in e.stderr:
                logger.info(f"No upstream branch configured (likely a new branch)")
            else:
                logger.error(f"Git pull failed: {e.stderr}")
                raise

    def add(self, file_path: str):
        self._run_git(["add", file_path])

    def commit(self, message: str):
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
            return
        except subprocess.CalledProcessError:
            # Exit code 1 means there ARE changes, proceed with commit
            pass
        
        self._run_git(["commit", "-m", message])

    def push(self):
        args = ["push"]
        if self.branch:
             # Set upstream if needed
             args.extend(["-u", "origin", self.branch])
        self._run_git(args)
