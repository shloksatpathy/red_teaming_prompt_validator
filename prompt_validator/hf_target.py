import torch
from transformers import pipeline


def make_target(model_id: str):
    """Return a `target(system_prompt, user_message) -> str` backed by a local Hugging Face chat model on the GPU."""
    pipe = pipeline("text-generation", model=model_id, dtype=torch.float16, device=0)

    def target(system_prompt: str, user_message: str) -> str:
        messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_message}]
        out = pipe(messages, max_new_tokens=128, do_sample=False)
        return out[0]["generated_text"][-1]["content"]

    return target
