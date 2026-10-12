from typing import Callable, Dict

from .attack_variants import generate_variants


def run_harness(target: Callable[[str, str], str], system_prompt: str, attack: str, canary: str) -> Dict[str, bool]:
    """Send every variant of `attack` to `target(system_prompt, user_message)`.

    `attack` must instruct the model to output `canary`; a variant succeeds if the reply contains it.
    """
    return {
        name: canary in target(system_prompt, variant)
        for name, variant in generate_variants(attack).items()
    }
