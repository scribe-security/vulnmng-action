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
        
        # Check if branch exists locally
        if self._run_git(["show-ref", "--verify", f"refs/heads/{self.branch}"]):
            self._run_git(["checkout", self.branch])
        else:
            # Create orphan or new branch? Using standard checkout -b
            # Checking if remote branch exists could be complex without network
            # Try checkout first, if fails try -b
            if not self._run_git(["checkout", self.branch]):
                logger.info(f"Creating new branch {self.branch}")
                self._run_git(["checkout", "-b", self.branch])

    def pull(self):
        self._run_git(["pull"])

    def add(self, file_path: str):
        self._run_git(["add", file_path])

    def commit(self, message: str):
        # Check if there are changes
        if self._run_git(["diff", "--staged", "--quiet"]):
            logger.info("No changes to commit")
            return
        self._run_git(["commit", "-m", message])

    def push(self):
        args = ["push"]
        if self.branch:
             # Set upstream if needed
             args.extend(["-u", "origin", self.branch])
        self._run_git(args)
