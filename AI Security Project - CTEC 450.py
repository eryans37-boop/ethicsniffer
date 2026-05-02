#!/usr/bin/env python3
"""
CTEC 450 - Adversarial ML Project
Author: Eric Ryans
Course: CTEC 450 | Instructor: Professor Carter
Date: April 2026

Trains a CNN on MNIST, attacks it with FGSM, then defends it with adversarial training.
Saves fgsm_comparison.png and results.png when done.

Run: python ai_security.py
     (requires: torch torchvision matplotlib numpy)
"""

import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from torchvision import datasets, transforms
from torch.utils.data import DataLoader
import matplotlib.pyplot as plt
import numpy as np

# ============================================================
# SETTINGS - change these if you want to experiment
# ============================================================

EPOCHS         = 5       # how many times to loop through training data
BATCH_SIZE     = 64      # how many images per batch
LEARNING_RATE  = 0.001   # how fast the model learns
EPSILON        = 0.3     # FGSM attack strength (0 = no attack, 1 = max)
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ============================================================
# 1. LOAD DATA
# ============================================================

def get_data():
    # MNIST normalization values (standard, from the dataset docs)
    transform = transforms.Compose([
        transforms.ToTensor(),
        transforms.Normalize((0.1307,), (0.3081,))
    ])

    train_data = datasets.MNIST("./data", train=True,  download=True, transform=transform)
    test_data  = datasets.MNIST("./data", train=False, download=True, transform=transform)

    train_loader = DataLoader(train_data, batch_size=BATCH_SIZE, shuffle=True)
    test_loader  = DataLoader(test_data,  batch_size=BATCH_SIZE, shuffle=False)

    print(f"Training samples: {len(train_data)}")
    print(f"Test samples:     {len(test_data)}")

    return train_loader, test_loader

# ============================================================
# 2. THE MODEL
# ============================================================

class SimpleCNN(nn.Module):
    """
    Two conv layers followed by two fully connected layers.
    Nothing fancy - just enough to get ~99% on clean MNIST.
    """
    def __init__(self):
        super(SimpleCNN, self).__init__()
        self.conv1 = nn.Conv2d(1, 32, kernel_size=3, padding=1)
        self.conv2 = nn.Conv2d(32, 64, kernel_size=3, padding=1)
        self.pool  = nn.MaxPool2d(2, 2)
        self.fc1   = nn.Linear(64 * 7 * 7, 128)
        self.fc2   = nn.Linear(128, 10)

    def forward(self, x):
        x = self.pool(F.relu(self.conv1(x)))   # 28x28 -> 14x14
        x = self.pool(F.relu(self.conv2(x)))   # 14x14 -> 7x7
        x = x.view(-1, 64 * 7 * 7)             # flatten
        x = F.relu(self.fc1(x))
        x = self.fc2(x)
        return x

# ============================================================
# 3. TRAIN (standard, no attack)
# ============================================================

def train_epoch(model, train_loader, optimizer, epoch_num):
    model.train()
    running_loss = 0.0

    for batch_idx, (images, labels) in enumerate(train_loader):
        images, labels = images.to(DEVICE), labels.to(DEVICE)

        optimizer.zero_grad()
        outputs = model(images)
        loss = F.cross_entropy(outputs, labels)
        loss.backward()
        optimizer.step()

        running_loss += loss.item()

        if batch_idx % 200 == 0:
            print(f"  Epoch {epoch_num}  [{batch_idx * len(images):>5}/{len(train_loader.dataset)}]"
                  f"  Loss: {loss.item():.4f}")

    return running_loss / len(train_loader)

# ============================================================
# 4. EVALUATE (clean accuracy)
# ============================================================

def evaluate(model, test_loader):
    model.eval()
    correct = 0

    with torch.no_grad():
        for images, labels in test_loader:
            images, labels = images.to(DEVICE), labels.to(DEVICE)
            preds = model(images).argmax(dim=1)
            correct += preds.eq(labels).sum().item()

    accuracy = 100.0 * correct / len(test_loader.dataset)
    return accuracy

# ============================================================
# 5. FGSM ATTACK
# ============================================================

def fgsm_attack(image, epsilon, grad):
    """
    Fast Gradient Sign Method (Goodfellow et al., 2015).
    Nudge each pixel a tiny bit in the direction that increases loss.
    The model gets confused even though the image looks the same to us.
    """
    sign_grad    = grad.sign()
    perturbed    = image + epsilon * sign_grad
    perturbed    = torch.clamp(perturbed, 0, 1)   # keep pixels in [0,1]
    return perturbed


def evaluate_fgsm(model, test_loader, epsilon):
    """Run the whole test set through FGSM and return accuracy."""
    model.eval()
    correct = 0

    for images, labels in test_loader:
        images, labels = images.to(DEVICE), labels.to(DEVICE)
        images.requires_grad = True

        # forward pass to get loss
        outputs = model(images)
        loss    = F.cross_entropy(outputs, labels)

        # backward to get gradients w.r.t. input
        model.zero_grad()
        loss.backward()

        # create adversarial examples
        adv_images = fgsm_attack(images, epsilon, images.grad.data)

        # evaluate on adversarial examples
        with torch.no_grad():
            adv_preds = model(adv_images).argmax(dim=1)
        correct += adv_preds.eq(labels).sum().item()

    return 100.0 * correct / len(test_loader.dataset)

# ============================================================
# 6. ADVERSARIAL TRAINING (defense)
# ============================================================

def train_adversarial_epoch(model, train_loader, optimizer, epoch_num, eps=0.2):
    """
    Mix adversarial examples into training so the model learns to handle them.
    Each batch: generate FGSM examples, train only on those.
    A lower epsilon than the attack so the model still generalizes well.
    """
    model.train()
    running_loss = 0.0

    for batch_idx, (images, labels) in enumerate(train_loader):
        images, labels = images.to(DEVICE), labels.to(DEVICE)
        images.requires_grad = True

        # forward + backward to get image gradients
        outputs = model(images)
        loss    = F.cross_entropy(outputs, labels)
        model.zero_grad()
        loss.backward()

        # make adversarial versions of this batch
        adv_images = fgsm_attack(images, eps, images.grad.data).detach()

        # train on the adversarial batch
        optimizer.zero_grad()
        adv_out  = model(adv_images)
        adv_loss = F.cross_entropy(adv_out, labels)
        adv_loss.backward()
        optimizer.step()

        running_loss += adv_loss.item()

        if batch_idx % 200 == 0:
            print(f"  Defense Epoch {epoch_num}"
                  f"  [{batch_idx * len(images):>5}/{len(train_loader.dataset)}]"
                  f"  Loss: {adv_loss.item():.4f}")

    return running_loss / len(train_loader)

# ============================================================
# 7. SAVE COMPARISON IMAGE (clean vs adversarial)
# ============================================================

def save_comparison_image(model, test_loader, epsilon, filename="fgsm_comparison.png"):
    model.eval()

    images, labels = next(iter(test_loader))
    images, labels = images.to(DEVICE), labels.to(DEVICE)
    images.requires_grad = True

    outputs = model(images)
    loss    = F.cross_entropy(outputs, labels)
    model.zero_grad()
    loss.backward()

    adv_images = fgsm_attack(images, epsilon, images.grad.data)

    fig, axes = plt.subplots(2, 5, figsize=(13, 6))
    fig.suptitle(f"FGSM Attack — epsilon = {epsilon}\n"
                 f"Top row: original   |   Bottom row: adversarial", fontsize=13)

    for i in range(5):
        # original image
        orig = images[i].cpu().detach().squeeze().numpy()
        axes[0][i].imshow(orig, cmap="gray")
        axes[0][i].set_title(f"True: {labels[i].item()}", fontsize=10)
        axes[0][i].axis("off")

        # adversarial image
        adv = adv_images[i].cpu().detach().squeeze().numpy()
        with torch.no_grad():
            adv_pred = model(adv_images[i].unsqueeze(0)).argmax(dim=1).item()
        axes[1][i].imshow(adv, cmap="gray")
        axes[1][i].set_title(f"Predicted: {adv_pred}", fontsize=10,
                              color="red" if adv_pred != labels[i].item() else "green")
        axes[1][i].axis("off")

    plt.tight_layout()
    plt.savefig(filename, dpi=120)
    plt.close()
    print(f"  Saved: {filename}")


# ============================================================
# 8. SAVE BAR CHART (accuracy comparison)
# ============================================================

def save_results_chart(results: dict, filename="results.png"):
    labels = list(results.keys())
    values = list(results.values())
    colors = ["#4CAF50", "#F44336", "#2196F3"]

    fig, ax = plt.subplots(figsize=(9, 6))
    bars = ax.bar(labels, values, color=colors, width=0.5)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.8,
                f"{val:.1f}%", ha="center", fontsize=13, fontweight="bold")

    ax.set_ylabel("Accuracy (%)", fontsize=12)
    ax.set_title("Model Accuracy: Baseline vs. Under Attack vs. After Defense", fontsize=13)
    ax.set_ylim(0, 108)
    ax.axhline(y=90, color="gray", linestyle="--", linewidth=1, label="90% target")
    ax.legend(fontsize=10)
    plt.tight_layout()
    plt.savefig(filename, dpi=120)
    plt.close()
    print(f"  Saved: {filename}")


# ============================================================
# MAIN
# ============================================================

def main():
    print(f"\nDevice: {DEVICE}")
    print("=" * 60)

    train_loader, test_loader = get_data()

    # ----------------------------------------------------------
    # PART 1 — Train baseline model
    # ----------------------------------------------------------
    print("\n[PART 1] Training baseline CNN on MNIST...")
    model     = SimpleCNN().to(DEVICE)
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE)

    for epoch in range(1, EPOCHS + 1):
        train_epoch(model, train_loader, optimizer, epoch)

    baseline_acc = evaluate(model, test_loader)
    print(f"\nBaseline accuracy (clean test set): {baseline_acc:.2f}%")

    torch.save(model.state_dict(), "baseline_model.pth")
    print("  Saved: baseline_model.pth")

    # ----------------------------------------------------------
    # PART 2 — FGSM attack
    # ----------------------------------------------------------
    print(f"\n[PART 2] Running FGSM attack (epsilon={EPSILON})...")
    attacked_acc = evaluate_fgsm(model, test_loader, EPSILON)
    print(f"Accuracy under FGSM attack: {attacked_acc:.2f}%")
    print(f"Accuracy drop:              {baseline_acc - attacked_acc:.2f}%")

    print("\n  Generating comparison image...")
    save_comparison_image(model, test_loader, EPSILON, "fgsm_comparison.png")

    # ----------------------------------------------------------
    # PART 3 — Adversarial training defense
    # ----------------------------------------------------------
    print("\n[PART 3] Defending with adversarial training...")
    defended_model = SimpleCNN().to(DEVICE)
    defended_model.load_state_dict(torch.load("baseline_model.pth"))  # start from baseline
    def_optimizer  = optim.Adam(defended_model.parameters(), lr=LEARNING_RATE * 0.5)

    for epoch in range(1, 4):   # 3 extra epochs of adversarial training
        train_adversarial_epoch(defended_model, train_loader, def_optimizer, epoch, eps=0.2)

    defended_clean_acc  = evaluate(defended_model, test_loader)
    defended_attack_acc = evaluate_fgsm(defended_model, test_loader, EPSILON)

    print(f"\nDefended model — clean accuracy:   {defended_clean_acc:.2f}%")
    print(f"Defended model — under FGSM attack: {defended_attack_acc:.2f}%")
    print(f"Recovery from attack:               {defended_attack_acc - attacked_acc:.2f}%")

    torch.save(defended_model.state_dict(), "defended_model.pth")
    print("  Saved: defended_model.pth")

    # ----------------------------------------------------------
    # PART 4 — Save charts
    # ----------------------------------------------------------
    print("\n[PART 4] Saving results chart...")
    results = {
        "Baseline\n(no attack)":    baseline_acc,
        "Under\nFGSM Attack":       attacked_acc,
        "Defended Model\n(FGSM attack)": defended_attack_acc,
    }
    save_results_chart(results, "results.png")

    # ----------------------------------------------------------
    # Summary
    # ----------------------------------------------------------
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    print(f"  Baseline accuracy (clean):          {baseline_acc:.2f}%")
    print(f"  Accuracy under FGSM (eps={EPSILON}):    {attacked_acc:.2f}%")
    print(f"  Drop from attack:                   {baseline_acc - attacked_acc:.2f}%")
    print(f"  Defended model (clean):             {defended_clean_acc:.2f}%")
    print(f"  Defended model (under FGSM attack): {defended_attack_acc:.2f}%")
    print(f"  Improvement from defense:           {defended_attack_acc - attacked_acc:.2f}%")
    print("=" * 60)
    print("\nOutput files:")
    print("  baseline_model.pth    — saved model weights")
    print("  defended_model.pth    — defended model weights")
    print("  fgsm_comparison.png   — clean vs adversarial images")
    print("  results.png           — accuracy bar chart")


if __name__ == "__main__":
    main()
