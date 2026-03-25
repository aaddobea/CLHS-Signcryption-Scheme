#Set up a virtual environment and install the dependencies
#Dependencies : pip install py_ecc and
# pip install py-ecc eth-utils

from eth_utils import keccak
import random
import time
import statistics
from py_ecc.optimized_bn128 import (
    add,
    multiply,
    pairing,
    G1,
    G2,
    normalize,
    curve_order
)

def benchmark_operation(operation, *args, num_runs=50, **kwargs):
    """Run an operation multiple times and return average time and result"""
    times = []
    result = None

    for _ in range(num_runs):
        start = time.perf_counter()
        result = operation(*args, **kwargs)
        end = time.perf_counter()
        times.append((end - start) * 10)  # Convert to milliseconds

    avg_time = statistics.mean(times)
    #std_dev = statistics.stdev(times) if len(times) > 1 else 0
    return result, avg_time


def print_point(name, pt):
    """Helper to print points in readable format"""
    if pt is None:
        print(f"{name}: O (point at infinity)")
    else:
        print(f"{name}: {normalize(pt)}")


def main():
    try:
        # Generate consistent test values
        alice_priv = random.randint(11509765413466789008765438967543, curve_order - 1)
        bob_priv = random.randint(1259087532556778976546453678654458, curve_order - 1)
        test_scalar = 578990

        print(f"\n=== Benchmarking (50 runs each) ===")
        print(f"Curve order: {curve_order}\n")

        # Benchmark G1 multiplication
        g1_mult_result, g1_avg = benchmark_operation(multiply, G1, alice_priv)
        print(f"G1 multiplication: {g1_avg:.4f} ms ")

        # Benchmark G2 multiplication
        g2_mult_result, g2_avg = benchmark_operation(multiply, G2, bob_priv)
        print(f"G2 multiplication: {g2_avg:.4f} ms ")

        # Benchmark point addition
        pt1 = multiply(G1, test_scalar)
        pt2 = multiply(G1, test_scalar + 2000)
        add_result, add_avg = benchmark_operation(add, pt1, pt2)
        print(f"G1 addition: {add_avg:.4f} ms ")

        # Benchmark pairing operation
        pairing_result, pair_avg = benchmark_operation(pairing, g2_mult_result, g1_mult_result)
        print(f"Pairing operation: {pair_avg:.4f} ms ")

        # Benchmark hash-to-curve
        message = b"This is my health message"

        def hash_op():
            msg_hash = int.from_bytes(keccak(message), 'big') % curve_order
            return multiply(G1, msg_hash)

        hash_result, hash_avg = benchmark_operation(hash_op)
        print(f"\nHash-to-curve (keccak + G1 mult): {hash_avg:.4f} ms ")

        # Print verification results
        print("\n=== Verification ===")
        print_point("Alice's public key", g1_mult_result)
        print_point("Bob's public key", g2_mult_result)
        print(
            f"Pairing verification: {pairing_result == pairing(G2, multiply(G1, (alice_priv * bob_priv) % curve_order))}")

    except ImportError as e:
        print(f"\nERROR: {e}")
        print("Install required packages with:")
        print("pip install py-ecc eth-utils pycryptodome")
    except Exception as e:
        print(f"\nERROR: {e}")


if __name__ == "__main__":
    main()
