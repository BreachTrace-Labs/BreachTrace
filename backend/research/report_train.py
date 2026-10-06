"""
Fine-tune the specialised report model (LoRA) and export it for llama.cpp.

Run on a GPU (a free Colab T4 takes about an hour for ~3k examples), NOT on
the user's machine. Install there:

    pip install "torch" "transformers>=4.45" "peft>=0.12" "trl>=0.12" "datasets" "accelerate"

Train on the dataset from research/report_distill.py:

    python research/report_train.py --data report_sft.jsonl \\
        --base Qwen/Qwen2.5-0.5B-Instruct --out reporter-0.5b

Then convert the merged model to a 4-bit GGUF with llama.cpp:

    git clone https://github.com/ggml-org/llama.cpp && pip install -r llama.cpp/requirements.txt
    python llama.cpp/convert_hf_to_gguf.py reporter-0.5b/merged --outfile reporter-f16.gguf --outtype f16
    llama.cpp/build/bin/llama-quantize reporter-f16.gguf breachtrace-reporter-q4_k_m.gguf Q4_K_M

Ship `breachtrace-reporter-q4_k_m.gguf` as the REPORT_MODEL_PATH file, but only
after research/report_eval.py's gate passes.

The dataset is TRL "prompt-completion" chat format, so the loss is computed on
the report JSON only, never on the system prompt or fact sheet.
"""
from __future__ import annotations

import argparse
import json


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", required=True, help="report_sft.jsonl from report_distill teach")
    parser.add_argument("--base", default="Qwen/Qwen2.5-0.5B-Instruct")
    parser.add_argument("--out", required=True)
    parser.add_argument("--epochs", type=float, default=3)
    parser.add_argument("--lr", type=float, default=2e-4)
    parser.add_argument("--rank", type=int, default=16)
    parser.add_argument("--batch", type=int, default=8)
    parser.add_argument("--max-length", type=int, default=2048)
    args = parser.parse_args()

    import torch
    from datasets import Dataset
    from peft import LoraConfig
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from trl import SFTConfig, SFTTrainer

    rows = [json.loads(line) for line in open(args.data, encoding="utf-8")]
    versions = {r["prompt_version"] for r in rows}
    if len(versions) != 1:
        raise SystemExit(f"Mixed prompt versions {versions}; regenerate the dataset with one prompt.")

    def to_dataset(split: str) -> Dataset:
        return Dataset.from_list([{"prompt": r["prompt"], "completion": r["completion"]}
                                  for r in rows if r["split"] == split])

    train, val = to_dataset("train"), to_dataset("val")
    print(f"train {len(train)}  val {len(val)}  prompt_version {versions.pop()}")

    tokenizer = AutoTokenizer.from_pretrained(args.base)
    model = AutoModelForCausalLM.from_pretrained(
        args.base, torch_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
    )

    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=train,
        eval_dataset=val if len(val) else None,
        peft_config=LoraConfig(
            r=args.rank, lora_alpha=args.rank * 2, lora_dropout=0.05, task_type="CAUSAL_LM",
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        ),
        args=SFTConfig(
            output_dir=args.out,
            num_train_epochs=args.epochs,
            learning_rate=args.lr,
            per_device_train_batch_size=args.batch,
            gradient_accumulation_steps=max(1, 16 // args.batch),
            lr_scheduler_type="cosine",
            warmup_ratio=0.05,
            logging_steps=10,
            eval_strategy="epoch" if len(val) else "no",
            save_strategy="epoch",
            max_length=args.max_length,
            completion_only_loss=True,
            report_to="none",
        ),
    )
    trainer.train()

    merged = trainer.model.merge_and_unload()
    merged.save_pretrained(f"{args.out}/merged")
    tokenizer.save_pretrained(f"{args.out}/merged")
    print(f"merged model saved to {args.out}/merged — convert it to GGUF (see module docstring)")


if __name__ == "__main__":
    main()
