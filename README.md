# Drone Anomaly Detection Dataset and Unsupervised Machine Learning

This project intends to comprehensively study the Wi-Fi-based DJI Edu Tello drone by collecting a dataset, extracting features from the captured packets, and developing an anomaly detector using unsupervised and incremental supervised ML models.

The paper for this research is available at [tentative]()

## Attack Vectors
There are five out of nine attack vectors implemented using Python scripts, contained in the **attack_vectors** directory
- Inject Instructions
- Data interception attack
- Replay Attack
- Payload Manipulation
- IP Spoofing

## Feature Extraction
The proposed feature extraction scripts, available in the **feature_extraction** directory, are derived from the [CIC IoT 2023 project](https://www.unb.ca/cic/datasets/iotdataset-2023.html) scripts. Five new features have been introduced, three existing features removed, and five modified to meet the needs of this project.
| New  | Removal | Modification |
| ------ | ------ |  ------  |
| Payload Length | Flow_duration | DS Status |
| Drone_port | Header_length | Drate and Srate |
| OUI of the Drone | MAC | Rate |
| Entropy |  | Inter-Arrival Time |
| Variance of Payload |  | Protocol Version |
## Feature Set
The proposed feature set in this project is available at the [ISOT datasets](https://onlineacademiccommunity.uvic.ca/isot/datasets/) with the modifications applied: 
| New  | Removal | Modification |
| ------ | ------ |  ------  |
| Payload Length | Flow_duration | DS Status |
| Drone_port | Header_length | Drate and Srate |
|  Entropy | MAC | Rate |
| Variance of Payload | Protocol Version | Inter-Arrival Time |
## Anomaly Detector Formulation

Three unsupervised ML algorithms: Isolation Forest (IF), Elliptic Envelope (EE), and Local Outlier Factor (LOF), are used for the anomaly detection model selection. Isolation Forest and Elliptic Envelope are fine-tuned in separate scripts to optimize their performance, and the finalized model is formulated using the Isolation Forest algorithm.

One incremental supervised ML algorithm, Adaptive Random Forest (ARF), is also used to explore the model's performance with streaming data.

The scripts are available in the directory **anomaly_detection_formulation**.


