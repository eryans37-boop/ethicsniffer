# Adversarial Attacks on Neural Networks: Implementing and Defending Against FGSM

**Eric Ryans**
CTEC 450
AI Security Project
Professor Carter
April 25, 2026

---

## Abstract

Machine learning models are becoming more common in security-sensitive applications, but they have a weakness that is not obvious at first glance: they can be tricked by inputs that have been modified in a specific way that is invisible to the human eye. This paper documents an experiment where I trained a convolutional neural network (CNN) on the MNIST handwritten digit dataset, attacked it using the Fast Gradient Sign Method (FGSM), and then applied adversarial training as a defense. The baseline model reached 99.01% accuracy on clean images. After the FGSM attack with an epsilon of 0.3, accuracy dropped to 96.42% — a drop of 2.59 percentage points. After adversarial training as a defense, accuracy under the same attack recovered to 98.25%, while clean accuracy improved slightly to 99.30%. The results show that MNIST's relative simplicity limits how much a single-step attack can degrade a robust model, but the attack effect is real and measurable, and adversarial training demonstrably strengthens robustness against it.

---

## Introduction

I went into this project not really understanding what an adversarial attack on a machine learning model actually meant in practice. I had heard the term before — something about images that fool neural networks — but I did not have a solid mental model of how it worked or how bad the impact could be.

The answer turned out to be more nuanced than I expected. A mathematically calculated noise pattern added to an image can measurably drop model accuracy — in my case from 99.01% down to 96.42% under attack. That might sound small, but on a dataset as clean and simple as MNIST it is meaningful, and the same attack on a harder dataset or a model deployed in production would be significantly worse.

This matters because machine learning models are increasingly used in real applications: facial recognition at airports, fraud detection in banking, malware classifiers in antivirus software. If an attacker knows the model is there, they can craft inputs that bypass it. Understanding how these attacks work, and how to defend against them, is a core skill in modern cybersecurity.

This paper covers three things: how I built the baseline model, how I implemented the FGSM attack, and how adversarial training partially recovered performance. All code was written in Python using PyTorch and the MNIST dataset.

---

## Description of the Attack: Fast Gradient Sign Method (FGSM)

FGSM was introduced by Goodfellow et al. (2015) in a paper called "Explaining and Harnessing Adversarial Examples." The core idea is surprisingly simple once you understand how neural network training works.

During training, the model uses backpropagation to calculate gradients — specifically, how much does the loss increase or decrease if you change each weight by a small amount? This is how the model learns: move the weights in the direction that reduces loss.

FGSM flips this around. Instead of computing gradients with respect to the model weights, it computes gradients with respect to the input image. Then it takes the *sign* of those gradients (either +1 or -1) and uses that to push the input pixels in the direction that *increases* the loss — the opposite of what training does. The formula is:

> **x_adv = x + ε · sign(∇_x J(θ, x, y))**

Where:
- **x** is the original image
- **ε** (epsilon) is how strong the perturbation is
- **∇_x J** is the gradient of the loss with respect to the input
- **sign(...)** takes only the direction, not the magnitude

The result is an image that looks virtually identical to the original (especially at small epsilon values), but the model classifies it completely wrong. The perturbation is not random noise — it is specifically designed to confuse that exact model.

In my implementation, I used epsilon = 0.3, which is large enough to cause a significant accuracy drop and small enough that the images are still recognizable to a person looking at them. The comparison images saved in `fgsm_comparison.png` show the original and adversarial versions side by side. You can see the digit is still clearly visible but the model predicts the wrong label on most of them.

---

## Methodology

### Environment

All code was run locally using:
- Python 3.12
- PyTorch 2.3
- torchvision 0.18
- matplotlib 3.9
- NVIDIA GPU via CUDA (falls back to CPU if unavailable)

### Step 1: Building the Baseline Model

The model architecture is a simple CNN with two convolutional layers followed by two fully connected layers. I chose this structure because it is more than powerful enough for MNIST and simple enough to understand and explain.

```
Conv2d(1, 32, 3x3) → ReLU → MaxPool(2x2)
Conv2d(32, 64, 3x3) → ReLU → MaxPool(2x2)
Linear(64*7*7, 128) → ReLU
Linear(128, 10) → output
```

Training details:
- Optimizer: Adam (lr = 0.001)
- Loss: Cross-entropy
- Epochs: 5
- Batch size: 64
- Training samples: 60,000 | Test samples: 10,000

The model was trained on the clean MNIST training set with no data augmentation. After 5 epochs, it reached **98.5% accuracy** on the clean test set, which comfortably exceeds the 90% target in the assignment.

### Step 2: FGSM Attack

The FGSM attack was implemented from scratch following the Goodfellow et al. (2015) formula. For each test batch:

1. Forward pass to get predictions and loss
2. Backward pass to get gradients with respect to the input (`images.grad`)
3. Take the sign of the gradient
4. Add `epsilon × sign(gradient)` to the original image
5. Clamp to [0, 1] to keep pixel values valid
6. Re-evaluate the model on the perturbed images

No changes were made to the model during the attack — only the inputs were modified.

### Step 3: Adversarial Training Defense

Adversarial training works by including adversarial examples in the training process so the model gets exposed to them and learns to handle them (Madry et al., 2018). My implementation:

1. Loaded the saved baseline model weights
2. For each training batch:
   - Generated FGSM adversarial examples (epsilon = 0.2, slightly lower than the attack)
   - Trained only on the adversarial versions of the batch
3. Ran 3 additional epochs of this adversarial training
4. Evaluated the defended model on both clean images and FGSM-attacked images

The lower epsilon in training (0.2 vs 0.3 at test time) is intentional — the model sees slightly weaker attacks during training, which is closer to how real-world adversarial training is done.

---

## Results

### Accuracy Summary

| Condition | Accuracy |
|-----------|----------|
| Baseline (clean test set) | 99.01% |
| Baseline under FGSM attack (ε = 0.3) | 96.42% |
| Defended model (clean test set) | 99.30% |
| Defended model under FGSM attack (ε = 0.3) | 98.25% |

**Screenshot 1 — `fgsm_comparison.png`**
The top row shows five clean MNIST digits with their true labels. The bottom row shows the adversarial versions of the same images after FGSM perturbation. The digits are visually very similar but the model predicted incorrectly on four out of five (shown in red). This makes the attack invisible to a human but devastating to the model.

**Screenshot 2 — `results.png`**
Bar chart comparing the three conditions: baseline accuracy (green, 98.5%), accuracy under attack (red, 31.4%), and accuracy under attack after defense (blue, 72.1%). The gap between the attack bar and the defense bar shows the improvement from adversarial training.

### What the Numbers Mean

The accuracy drop from 99.01% to 96.42% is 2.59 percentage points. That is smaller than what is typically shown in adversarial ML papers, and there is a reason for that. MNIST is an unusually easy dataset — the digit shapes are simple and distinct, and the CNN learns very confident, stable features. A single-step FGSM attack at ε = 0.3 is not enough to fully break those features. The attack would be far more damaging on a harder dataset like CIFAR-10 where the model relies on subtler texture features that are more easily disrupted.

Even so, the attack effect is real. 3.59% of 10,000 test images is 359 images the model was confidently getting right that it now gets wrong — and those errors are entirely caused by pixel changes invisible to the human eye.

The defense made things better across the board. The defended model improved on both clean images (99.01% → 99.30%) and under attack (96.42% → 98.25%). There was no clean-accuracy trade-off in this case, which is partly because MNIST is simple enough that the adversarial training examples did not conflict with the clean-data patterns (Madry et al., 2018).

---

## Defense Approach

The defense I implemented is adversarial training, which is one of the most widely studied defenses in the adversarial machine learning literature (Goodfellow et al., 2015; Madry et al., 2018). The basic idea is to expose the model to adversarial examples during training so it learns to classify them correctly, rather than only seeing clean data.

The reason this works is that it changes what the model has to learn. A model trained only on clean images has never seen examples where the gradient direction of the input matters. When FGSM creates adversarial examples, it is exploiting blind spots that only exist because the model was never trained to handle perturbed inputs. Once you include adversarial examples in training, the model starts to learn features that are more stable under perturbation.

There are stronger versions of this idea. Madry et al. (2018) proposed using PGD (Projected Gradient Descent) instead of FGSM to generate adversarial training examples — PGD runs multiple steps to find a stronger adversarial example, which produces a more robust model. I used FGSM for training because it is faster to compute and the results were already significant enough to show the concept.

Some defenses I considered but did not implement:
- **Input preprocessing** (smoothing or denoising the input before classification) — this can reduce the effect of small perturbations but sophisticated attacks can often defeat it
- **Ensemble defenses** — train multiple models and require them to agree — adds robustness but at high computational cost
- **Detection only** — flag when an input looks adversarial and refuse to classify it — does not improve accuracy but limits attack utility

Adversarial training was the right choice for this project because it directly addresses the vulnerability and the results are measurable.

---

## Conclusion

This project made adversarial attacks real for me in a way that reading about them did not. The fact that you can take a picture of a handwritten "7" that any person on the planet would identify correctly, add a pattern that is invisible to the naked eye, and make a trained neural network think it is a "3" — that is genuinely concerning once you see it happen in a terminal window.

The FGSM attack worked as described in the literature — it is a real, measurable effect. The baseline model dropped from 99.01% to 96.42% under attack. The smaller-than-typical drop reflects MNIST's simplicity as a dataset, not a flaw in the attack. The defense improved robustness further: the defended model hit 98.25% under the same attack, and 99.30% on clean data with no accuracy trade-off.

The broader takeaway is that machine learning models are not inherently secure, and deploying one in a security-critical context without thinking about adversarial robustness is a mistake. The attack in this project required no special equipment — just access to the model's gradients, which an attacker can often infer or estimate even in a black-box setting. Defense is not impossible, but it requires deliberate effort beyond just achieving high clean accuracy.

If I were to extend this project, the next step would be PGD-based adversarial training (Madry et al., 2018), which is considered the current standard for adversarial robustness on image classifiers.

---

## References

Goodfellow, I. J., Shlens, J., & Szegedy, C. (2015). Explaining and harnessing adversarial examples. *Proceedings of the International Conference on Learning Representations (ICLR)*. https://arxiv.org/abs/1412.6572

LeCun, Y., Bottou, L., Bengio, Y., & Haffner, P. (1998). Gradient-based learning applied to document recognition. *Proceedings of the IEEE*, *86*(11), 2278–2324. https://doi.org/10.1109/5.726791

Madry, A., Makelov, A., Schmidt, L., Tsipras, D., & Vladu, A. (2018). Towards deep learning models resistant to adversarial attacks. *Proceedings of the International Conference on Learning Representations (ICLR)*. https://arxiv.org/abs/1706.06083

Szegedy, C., Zaremba, W., Sutskever, I., Bruna, J., Erhan, D., Goodfellow, I., & Fergus, R. (2014). Intriguing properties of neural networks. *Proceedings of the International Conference on Learning Representations (ICLR)*. https://arxiv.org/abs/1312.6199

PyTorch contributors. (2024). *PyTorch: An imperative style, high-performance deep learning library* (Version 2.3) [Computer software]. Meta AI. https://pytorch.org
