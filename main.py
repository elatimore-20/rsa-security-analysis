from attacks import (
    broadcast_attack_demo,
    broadcast_attack_failure_demo,
    broadcast_attack_with_padding_demo,
    fermat_attack_demo,
    fermat_attack_failure_demo,
    common_modulus_attack_demo,
)

def main():
    print("=== Running RSA Security Project ===")

    broadcast_attack_demo()
    broadcast_attack_failure_demo()
    broadcast_attack_with_padding_demo()
    fermat_attack_demo()
    fermat_attack_failure_demo()
    common_modulus_attack_demo()

    print("\nAll demos completed.")

if __name__ == "__main__":
    main()