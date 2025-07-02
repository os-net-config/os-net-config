=============================
Contributing to os-net-config
=============================

Get the code
============

`Fork the project`__ if you haven't already done so. Configure your clone to
point at your fork and keep a reference on the upstream repository. You can also
take the opportunity to configure ``git`` to use SSH for pushing and
``https://`` for pulling.

__ https://github.com/os-net-config/os-net-config/fork

.. code:: console

   $ git remote remove origin
   $ git remote add upstream https://github.com/os-net-config/os-net-config
   $ git remote add origin https://github.com/rjarry/os-net-config
   $ git fetch --all
   Fetching origin
   From https://github.com/rjarry/os-net-config
    * [new branch]                master     -> origin/master
   Fetching upstream
   From https://github.com/os-net-config/os-net-config
    * [new branch]                master     -> upstream/master
   $ git config url.git@github.com:.pushinsteadof https://github.com/

Create a local branch named after the topic of your future commits:

.. code:: console

   $ git checkout -b drivers-autoprobe -t upstream/master
   branch 'drivers-autoprobe' set up to track 'upstream/master'.
   Switched to a new branch 'drivers-autoprobe'

Patch the code. Ensure that everything works as expected. Ensure that you did
not break anything.

- Do not forget to update the documentation and examples, if applicable.
- If you are adding a new feature, consider writing new tests.
- Run the linters and tests with ``tox``.

Git commit rules
================

Once you are happy with your work, you can create a commit (or several commits).
Follow these general rules:

- Limit the first line (title) of the commit message to 60 characters.
- Use a short prefix for the commit title for readability with `git log
  --oneline`. Do not use the `fix:` nor `feature:` prefixes. See recent commits
  for inspiration.
- Only use lower case letters for the commit title except when quoting symbols
  or known acronyms.
- Use the body of the commit message to actually explain what your patch does
  and why it is useful. Even if your patch is a one line fix, the description
  is not limited in length and may span over multiple paragraphs. Use proper
  English syntax, grammar and punctuation.
- Address only one issue/topic per commit.
- Describe your changes in **imperative mood**, e.g. *"make xyzzy do frotz"*
  instead of *"[This patch] makes xyzzy do frotz"* or *"[I] changed xyzzy to do
  frotz"* or *"adding xyzzy for frotz"*, as if you are giving orders to the
  codebase to change its behaviour.
- If you are fixing an issue, add an appropriate ``Closes: <ISSUE_URL>``
  trailer.
- If you are fixing a regression introduced by another commit, add a
  ``Fixes: <SHORT_ID_12_LONG> "<COMMIT_TITLE>"`` trailer.
- When in doubt, follow the format and layout of the recent existing commits.
- The following trailers are accepted in commits. If you are using multiple
  trailers in a commit, it's preferred to also order them according to this
  list.

  * ``Closes: <URL>`` closes the referenced issue.
  * ``Fixes: <sha> ("<title>")`` reference the commit that introduced
    a regression.
  * ``Link:`` to store any URL that may be relevant to a commit
  * ``Suggested-by:``
  * ``Requested-by:``
  * ``Reported-by:``
  * ``Co-authored-by:``
  * ``Signed-off-by:`` compulsory!
  * ``Tested-by:``
  * ``Reviewed-by:``
  * ``Acked-by:``

There is a great reference for commit messages in the `Linux kernel
documentation`__.

__ https://www.kernel.org/doc/html/latest/process/submitting-patches.html#describe-your-changes

.. important::

   You must sign-off your work using ``git commit --signoff``. Follow the `Linux
   kernel developer's certificate of origin`__ for more details. All
   contributions are made under the `Apache 2.0`__ license. Please use your real
   name and not a pseudonym. Here is an example::

       Signed-off-by: Robin Jarry <rjarry@redhat.com>

   __ https://www.kernel.org/doc/html/latest/process/submitting-patches.html#sign-your-work-the-developer-s-certificate-of-origin
   __ https://www.apache.org/licenses/LICENSE-2.0.txt

Once you are happy with your commits, you can verify that they are correct with
the following command:

.. code:: console

   $ ./check-commits upstream/master..
   ok    [1/1] 'sriov: add drivers_autoprobe attribute to pf'
   2/2 valid commits

Create a pull request
=====================

You can then push your topic branch on your fork:

.. code:: console

   $ git push origin drivers-autoprobe
   ...
   remote:
   remote: Create a pull request for 'drivers-autoprobe' on GitHub by visiting:
   remote:      https://github.com/rjarry/os-net-config/pull/new/drivers-autoprobe
   remote:
   To github.com:rjarry/os-net-config
    * [new branch]                drivers-autoprobe -> drivers-autoprobe

Before your pull request can be applied, it needs to be reviewed and approved
by project members.

Address review comments and rebase
==================================

Address **all** comments from reviewers, if any. Amend your commit(s) and force
push on your topic branch. This will automatically update the pull requests. If
your branch gets out of date and cannot be rebased without conflicts, you will
need to do it yourself before force pushing again:

.. code:: console

   $ vi os_net_config/objects.py
   $ git add -u
   $ git commit --amend
   $ git pull --rebase upstream master
   From https://github.com/os-net-config/os-net-config
    * branch                      master     -> FETCH_HEAD
   Auto-merging os_net_config/objects.py
   CONFLICT (content): Merge conflict in os_net_config/objects.py
   error: could not apply ca5793f48bf5... sriov: add drivers_autoprobe attribute to pf
   ...
   $ git status -sb
   ## HEAD (no branch)
   ...
   UU os_net_config/objects.py
   ...
   $ vi os_net_config/objects.py
   $ git add os_net_config/objects.py
   $ git rebase --continue
   [detached HEAD 6e822c23cdda] sriov: add drivers_autoprobe attribute to pf
    14 files changed, 180 insertions(+), 16 deletions(-)
   Successfully rebased and updated refs/heads/drivers-autoprobe.
   $ git push --force origin drivers-autoprobe
   ...
   To github.com:rjarry/os-net-config
    + c6b0da31b353...db40fef5ed91 drivers-autoprobe -> drivers-autoprobe (forced update)
