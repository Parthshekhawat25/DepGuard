"""Safe parser for Python requirements.txt content.

This module only parses text. It never imports, installs, or executes
anything referenced by a requirements file.
"""

from dataclasses import dataclass, field
import re
from typing import List, Literal, Optional

from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version


IssueType = Literal["invalid", "unsupported"]


@dataclass
class ParsedDependency:
    """A valid registry dependency extracted from requirements.txt."""

    package_name: str
    requested_version: Optional[str]
    version_specifier: str
    is_pinned: bool
    line_number: int
    raw_line: str
    extras: List[str] = field(default_factory=list)
    marker: Optional[str] = None


@dataclass
class RequirementIssue:
    """A line that cannot be scanned as a normal PyPI dependency."""

    line_number: int
    raw_line: str
    reason: str
    issue_type: IssueType


@dataclass
class ParseResult:
    """Structured parser output for later vulnerability analysis."""

    dependencies: List[ParsedDependency] = field(default_factory=list)
    pinned_dependencies: List[ParsedDependency] = field(default_factory=list)
    unpinned_dependencies: List[ParsedDependency] = field(default_factory=list)
    invalid_lines: List[RequirementIssue] = field(default_factory=list)
    unsupported_lines: List[RequirementIssue] = field(default_factory=list)

    @property
    def issues(self) -> List[RequirementIssue]:
        """Return invalid and unsupported lines in source order."""

        return sorted(
            [*self.invalid_lines, *self.unsupported_lines],
            key=lambda issue: issue.line_number,
        )


def normalize_package_name(name: str) -> str:
    """Normalize a package name according to Python package naming rules."""

    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(content: str) -> ParseResult:
    """Parse requirements.txt content without executing any requirement.

    Exact ``package==version`` requirements are returned as pinned
    dependencies. Requirements with ranges, exclusions, markers only, or no
    version are returned as unpinned because an exact version cannot be
    determined safely.
    """

    if not isinstance(content, str):
        raise TypeError("requirements content must be a string")

    result = ParseResult()

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped_line = raw_line.strip()

        if not stripped_line or stripped_line.startswith("#"):
            continue

        line = _strip_inline_comment(stripped_line)
        if not line:
            continue

        unsupported_reason = _unsupported_line_reason(line)
        if unsupported_reason:
            result.unsupported_lines.append(
                RequirementIssue(
                    line_number=line_number,
                    raw_line=raw_line,
                    reason=unsupported_reason,
                    issue_type="unsupported",
                )
            )
            continue

        try:
            requirement = Requirement(line)
        except (InvalidRequirement, ValueError) as exc:
            result.invalid_lines.append(
                RequirementIssue(
                    line_number=line_number,
                    raw_line=raw_line,
                    reason=f"Invalid requirement: {exc}",
                    issue_type="invalid",
                )
            )
            continue

        if requirement.url:
            result.unsupported_lines.append(
                RequirementIssue(
                    line_number=line_number,
                    raw_line=raw_line,
                    reason=(
                        "Direct URL, VCS, and local-path requirements are "
                        "not supported; only registry packages are accepted"
                    ),
                    issue_type="unsupported",
                )
            )
            continue

        exact_version = _exact_pinned_version(requirement)
        dependency = ParsedDependency(
            package_name=normalize_package_name(requirement.name),
            requested_version=exact_version,
            version_specifier=str(requirement.specifier),
            is_pinned=exact_version is not None,
            line_number=line_number,
            raw_line=raw_line,
            extras=sorted(requirement.extras),
            marker=str(requirement.marker) if requirement.marker else None,
        )

        result.dependencies.append(dependency)
        if dependency.is_pinned:
            result.pinned_dependencies.append(dependency)
        else:
            result.unpinned_dependencies.append(dependency)

    return result


def _exact_pinned_version(requirement: Requirement) -> Optional[str]:
    """Return an exact version only for a single, valid ``==`` specifier."""

    specifiers = list(requirement.specifier)
    if len(specifiers) != 1 or specifiers[0].operator != "==":
        return None

    version = specifiers[0].version
    if "*" in version:
        return None

    try:
        Version(version)
    except InvalidVersion:
        return None

    return version


def _strip_inline_comment(line: str) -> str:
    """Remove a conventional inline comment while preserving URL fragments."""

    comment_start = re.search(r"\s+#", line)
    if comment_start:
        return line[: comment_start.start()].rstrip()
    return line


def _unsupported_line_reason(line: str) -> Optional[str]:
    """Identify requirement-file directives and non-registry references."""

    if line.startswith("-"):
        return "Requirement-file options and directives are not supported"

    if line.startswith(
        (
            "./",
            "../",
            ".\\",
            "..\\",
            "/",
            "\\",
            "git+",
            "hg+",
            "svn+",
            "bzr+",
            "http://",
            "https://",
            "file://",
        )
    ):
        return (
            "VCS, URL, and local-path requirements are not supported; "
            "only registry packages are accepted"
        )

    return None
