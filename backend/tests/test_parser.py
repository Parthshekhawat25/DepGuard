from app.services.parser import parse_requirements


def test_exact_pinned_dependencies():
    result = parse_requirements("requests==2.31.0")

    assert len(result.dependencies) == 1
    dependency = result.pinned_dependencies[0]
    assert dependency.package_name == "requests"
    assert dependency.requested_version == "2.31.0"
    assert dependency.version_specifier == "==2.31.0"
    assert dependency.is_pinned is True
    assert result.unpinned_dependencies == []


def test_unpinned_dependencies():
    result = parse_requirements(
        """
        flask
        urllib3>=2.0
        """
    )

    assert [dependency.package_name for dependency in result.unpinned_dependencies] == [
        "flask",
        "urllib3",
    ]
    assert all(dependency.requested_version is None for dependency in result.unpinned_dependencies)
    assert result.pinned_dependencies == []


def test_minimum_and_maximum_version_constraints_remain_unpinned():
    result = parse_requirements(
        """
        django>=4.0,<5.0
        urllib3<=2.0
        """
    )

    assert len(result.unpinned_dependencies) == 2
    assert result.unpinned_dependencies[0].version_specifier in {
        "<5.0,>=4.0",
        ">=4.0,<5.0",
    }
    assert result.unpinned_dependencies[1].version_specifier == "<=2.0"
    assert all(dependency.requested_version is None for dependency in result.dependencies)


def test_comments_blank_lines_whitespace_and_name_normalization():
    result = parse_requirements(
        """
        # A full-line comment

          Requests_Security==1.2.3  # An inline comment
        """
    )

    assert len(result.dependencies) == 1
    dependency = result.pinned_dependencies[0]
    assert dependency.package_name == "requests-security"
    assert dependency.requested_version == "1.2.3"
    assert dependency.line_number == 4


def test_invalid_requirement_lines_are_reported():
    result = parse_requirements(
        """
        requests=>2.0
        not a valid requirement
        """
    )

    assert len(result.invalid_lines) == 2
    assert [issue.issue_type for issue in result.invalid_lines] == ["invalid", "invalid"]
    assert result.dependencies == []


def test_unsupported_requirement_lines_are_reported():
    result = parse_requirements(
        """
        -r base.txt
        git+https://github.com/example/project.git
        example @ https://example.com/example.whl
        """
    )

    assert len(result.unsupported_lines) == 3
    assert all(issue.issue_type == "unsupported" for issue in result.unsupported_lines)
    assert result.dependencies == []


def test_empty_requirements_file():
    result = parse_requirements("  \n\n# only a comment\n")

    assert result.dependencies == []
    assert result.pinned_dependencies == []
    assert result.unpinned_dependencies == []
    assert result.invalid_lines == []
    assert result.unsupported_lines == []
    assert result.issues == []
