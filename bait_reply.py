import random


def bait_reply(history: list):
    bait_prompts = [
        "Okay sir, but my bank app is slow. Can you send full details again?",
        "I don't understand UPI, can you tell step by step?",
        "Is this account correct? Please send account number and IFSC again",
        "My brother will pay, can you send payment details once more?",
        "I tried but it failed. Which UPI or bank should I use?"
    ]
    return random.choice(bait_prompts)
