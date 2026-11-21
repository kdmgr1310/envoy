load("@base_pip3//:requirements.bzl", "requirement")
load("@rules_python//python:defs.bzl", "py_test")
load("@rules_python//python:pip.bzl", "compile_pip_requirements")

licenses(["notice"])  # Apache 2

exports_files([
    "entry_point.py",
])

py_test(
    name = "packaging_requirements_test",
    srcs = ["packaging_requirements_test.py"],
    data = ["requirements.txt"],
    deps = [requirement("packaging")],
)

compile_pip_requirements(
    name = "requirements",
    src = "requirements.in",
    extra_args = [
        "--allow-unsafe",
        "--generate-hashes",
        "--reuse-hashes",
        "--resolver=backtracking",
    ],
)
