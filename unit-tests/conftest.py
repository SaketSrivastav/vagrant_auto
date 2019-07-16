def pytest_addoption(parser):
    parser.addoption("--all", action="store_true",
                    help="run all combinations")
    parser.addoption ('--count', default=1, type='int',
                    metavar='count',
                    help='Run each test the specified number of times')
