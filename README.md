
# SDN Security - A Mininet Simulated Intrussion Detection System

Software-Defined Networking (SDN) architectures introduce new security challenges, as the centralized control plane can become a prime target for attackers. To address these problems, this work presents an SDN-based Intrusion Detection System (IDS) that integrates a Long Short-Term Memory (LSTM) deep learning model to detect anomalous network activity in real-time. The LSTM model that is trained on the NSL-KDD dataset, is embedded directly into the SDN
controller (POX), allowing all network traffic to be analyzed for unusual behavior. The proposed IDS solution is demonstrated and evaluated using the Mininet network emulator, which validates the effectiveness of this approach in accurately identifying intrusions within the SDN environment.


## Features

- **Real-time Anomaly Detection**: Utilizes an LSTM deep learning model to identify abnormal network activities.

- **Integration with POX Controller**: The IDS is embedded in the POX SDN controller, enabling centralized monitoring and analysis.

- **NSL-KDD Dataset**: The LSTM model is trained using the NSL-KDD dataset, a well-known dataset for network intrusion detection.

- **Mininet Emulation**: The system is tested and validated using Mininet, an SDN network emulator, to demonstrate its effectiveness.



## Installation

#### Prerequisites
```bash
  Python 3.x
  Git
  POX SDN controller
  Mininet
  TensorFlow
  Keras
  NumPy
  Scikit-learn
```


    
## Usage

#### Train the LSTM Model:

The LSTM model should be trained using the NSL-KDD dataset. The training scripts are provided in the model/ directory. You can use feature_selection.ipynb and kdd.ipynb notebooks to preprocess the dataset and train the model.

#### Deploy the IDS:

Once the model is trained, deploy the IDS by integrating it with the POX controller as described in the installation steps.

#### Monitor Network Traffic:

The IDS will monitor the network traffic in real-time and log any detected anomalies. You can view these logs in the POX controller output.


## Project Structure

- gui/: Contains the graphical user interface components(using python tkinter)
- mininet/: Includes Mininet scripts and custom topologies.(integration with pox controller)
- model/: Contains scripts and notebooks for data(LSTM model feature selection,preprocessing and training)
