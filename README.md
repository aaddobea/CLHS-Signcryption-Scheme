# CLHS-Signcryption-Scheme
A certificateless Hybrid Signcryption Scheme for decentralized data management on Blockchain.

# A Blockchain-Enabled Hybrid Signcryption Scheme for Decentralized Data Management

[![DOI](https://img.shields.io/static/v1?label=DOI&message=10.1007/s12083-026-02207-9&color=blue)](https://doi.org/10.1007/s12083-026-02207-9)

## Overview

This repository contains the implementation and experimental code for the paper:

**"A Blockchain-Enabled Hybrid Signcryption Scheme for Decentralized Data Management"**  
*Published in: Peer-to-Peer Networking and Applications, 2026*  
DOI: [10.1007/s12083-026-02207-9](https://link.springer.com/article/10.1007/s12083-026-02207-9)

## Abstract

Blockchain technology offers immutable evidence in decentralized data management in modern medical systems. However, securing Electronic Medical Records (EMR) within the blockchain framework remains a critical challenge due to the inherent storage limitations and computational overhead from existing public key methods. To address such issues, this paper proposes a **certificateless hybrid signcryption scheme** that integrates a tag-based key encapsulation mechanism (tag-KEM) with a data encapsulation mechanism (DEM), to enable secure and efficient EMR data management.

Our approach addresses key limitations in existing blockchain systems by combining lightweight cryptographic operations based on Elliptic Curve Cryptography (ECC) with efficient decentralized off-chain storage to accommodate large-scale growing health data. By employing ECC operations, the scheme significantly reduces computational complexity and enhances blockchain transaction throughput.

## Key Results

- **40.01%–97.71% reduction** in computational cost compared to existing methods
- Improved storage efficiency through decentralized off-chain storage
- Enhanced blockchain transaction throughput with lightweight ECC operations

## Repository Structure

## File Descriptions

| File | Description |
|------|-------------|
| `fastecdsa.py` | Fast implementation of elliptic curve operations for signcryption |
| `pairing_Ethereum.py` | Ethereum-compatible pairing functions for blockchain integration |
| `scheme.tex` | LaTeX source for the cryptographic scheme description |
| `signcrypt1pub.vp` | Visual Paradigm diagram of the signcryption protocol |
| `analysis code for sections 4 and 5/` | Experimental code for reproducing performance analysis results |
| `fig2.pdf` | Figure 2: Proposed scheme architecture |
| `fig4.pdf` | Figure 4: Performance comparison results |

## Requirements

- Python 3.8+
- Required packages: `ecdsa`, `pycryptodome`, `web3.py` (for Ethereum integration)

## Citation

If you use this code or find our work useful, please cite:

```bibtex
@article{addobea2026blockchain,
  title={A blockchain-enabled hybrid signcryption scheme for decentralized data management},
  author={Addobea, Abigail Akosua and others},
  journal={Peer-to-Peer Networking and Applications},
  year={2026},
  publisher={Springer},
  doi={10.1007/s12083-026-02207-9}
}


To execute the experiments in the paper, the execution procedure can be found in the analysis code for sections 4 and  5 file.

