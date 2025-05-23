import pandas as pd
import joblib
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

df = pd.read_csv('KDDTest.csv')
features = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'logged_in', 'wrong_fragment',
    'same_srv_count', 'same_srv_rate'
]
X_test = df[features]
y_test = df['label']

le_protocol = joblib.load('model/le_protocol.pkl')
le_service = joblib.load('model/le_service.pkl')
le_flag = joblib.load('model/le_flag.pkl')
model = joblib.load('model/ids_model.pkl')

# Use .loc to avoid SettingWithCopyWarning
X_test.loc[:, 'protocol_type'] = le_protocol.transform(X_test['protocol_type'])
X_test.loc[:, 'service'] = le_service.transform(X_test['service'])
X_test.loc[:, 'flag'] = le_flag.transform(X_test['flag'])

y_pred = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred))