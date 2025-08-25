import numpy as np
import joblib  # Used to save and load scikit-learn models
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import MinMaxScaler
import os

# --- Load the Prepared Data ---
print("Loading data...")
try:
    X_train = np.load('X_train.npy')
    X_test = np.load('X_test.npy')
    y_train = np.load('y_train.npy')
    y_test = np.load('y_test.npy')
    print("Data loaded successfully.")
    print(f"X_train shape: {X_train.shape}")
    print(f"y_train shape: {y_train.shape}")
    print(f"X_test shape: {X_test.shape}")
    print(f"y_test shape: {y_test.shape}")

except FileNotFoundError:
    print("Error: .npy files not found. Please ensure 'prepare_data.py' was run successfully.")
    exit()
except Exception as e:
    print(f"An error occurred while loading data: {e}")
    exit()

# --- Preprocess Data with a Scaler ---
# Scaling is crucial for distance-based algorithms like KNN
print("\nScaling data...")
scaler = MinMaxScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
print("Data scaled successfully.")

# --- Build and Train the KNN Model ---
print("\nBuilding and training the K-Nearest Neighbors (KNN) model...")
# Choose a value for 'n_neighbors'. A good starting point is 5.
n_neighbors = 5
model = KNeighborsClassifier(n_neighbors=n_neighbors)

# Train the model
model.fit(X_train_scaled, y_train)
print("Training complete.")

# --- Evaluate the Model on Test Data ---
print("\nEvaluating the model on test data...")
y_pred = model.predict(X_test_scaled)

print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Normal (0)', 'Attack (1)']))

print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)

# --- Save the Final Trained Model and Scaler ---
model_filename = 'network_ids_knn_model.joblib'
scaler_filename = 'data_scaler.joblib'

print(f"\nSaving the trained model to '{model_filename}'...")
joblib.dump(model, model_filename)

print(f"Saving the data scaler to '{scaler_filename}'...")
joblib.dump(scaler, scaler_filename)

print("\nModel and scaler saved. You can now use them in your sniffer application.")
