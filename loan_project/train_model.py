# train_model.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
import joblib
import warnings

warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')

# 1. Load the dataset
print("Loading data from train.csv...")
data = pd.read_csv('train.csv')
print("Columns found in CSV:", data.columns.tolist())

# 2. Preprocess data according to the new columns
print("Preprocessing data...")
# Fill any potential missing values
data = data.dropna()

# Convert the categorical 'Employment_Status' column
data = pd.get_dummies(data, columns=['Employment_Status'], drop_first=True)

# 3. Select Features (X) and Target (y) from the new columns
# Assuming 'Loan_Approved' is the target and the rest are features
features = [
    'Age', 
    'Income', 
    'Credit_Score', 
    'Loan_Amount', 
    'Loan_Term',
    'Employment_Status_Unemployed' # This is created by get_dummies
]
X = data[features]
y = data['Loan_Approved']

# 4. Split and Train a Logistic Regression model
print("Training model...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# 5. Evaluate and save the model
print(f"Model Accuracy: {accuracy_score(y_test, model.predict(X_test)):.2f}")
joblib.dump(model, 'loan_model.joblib')
print("Model saved as 'loan_model.joblib'")