# Table 2: S3 Failure Classifier Performance Metrics

Overall Multiclass Accuracy: **68.57%** | Macro F1-Score: **0.447** | Weighted F1-Score: **0.750**

| Injected Ground Truth Class | Support (N) | Precision | Recall | F1-Score | Classified Causes Distribution |
| :--- | :---: | :---: | :---: | :---: | :--- |
| Security Failure (Attacks / Floor Violations) | 140 | 83.3% | 71.4% | 0.769 | security_failure: 100, loss_timeout: 40 |
| MTU / Fragmentation Limit | 10 | 0.0% | 0.0% | 0.000 | loss_timeout: 10 |
| Packet Loss / Timeout | 12 | 11.8% | 100.0% | 0.211 | loss_timeout: 12 |
| Normal / Clean Execution | 188 | 100.0% | 68.1% | 0.810 | security_failure: 20, loss_timeout: 40, none: 128 |