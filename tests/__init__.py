import os
import sys
import unittest

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def run_tests():
    """
    Run all tests in the tests directory.
    
    This function:
    1. Discovers all test files (test_*.py) in the tests directory
    2. Runs them with verbose output
    3. Returns the test results
    
    Usage:
        python -m tests
    """
    print("\n" + "="*50)
    print("Starting Authentication API Tests")
    print("="*50)
    
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.dirname(__file__), pattern='test_*.py')
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "="*50)
    print("Test Summary")
    print("="*50)
    print(f"Total Tests: {result.testsRun}")
    print(f"Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failed: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    return result

if __name__ == '__main__':
    run_tests() 