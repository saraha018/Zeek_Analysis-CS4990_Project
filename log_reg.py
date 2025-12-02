#!/usr/bin/env python3
"""
Train machine learning model to classify network traffic as benign or malware.
(Logistic Regression version, with leakage checks)
"""
import argparse
import pandas as pd
import numpy as np
from pathlib import Path
import pickle
import json
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score, roc_curve
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns
import config
from joblib import dump


def load_features(features_file):
    """
    Load features from CSV file.
    
    Args:
        features_file: Path to features CSV file
        
    Returns:
        DataFrame with features
    """
    df = pd.read_csv(features_file)
    return df


def prepare_data(df):
    """
    Prepare data for training.
    
    Args:
        df: DataFrame with features and labels
        
    Returns:
        X (features), y (labels), feature_names
    """
    # Check if label column exists
    if 'label' not in df.columns:
        raise ValueError("No 'label' column found in features. Please ensure labels are present.")
    
    # Separate features and labels
    y = df['label'].values

    # Remove non-feature columns (labels, IDs, and any string columns)
    # You can add more here if your CSV has extra label-like columns
    exclude_cols = [
        'label',
        'pcap_name',
        'sample_id',
        # add anything obviously label-ish if present:
        'attack_name',
        'attack_category',
        'is_malicious',
        'ground_truth',
    ]
    
    # Only include numeric columns as features
    candidate_feature_cols = []
    for col in df.columns:
        if col not in exclude_cols:
            if pd.api.types.is_numeric_dtype(df[col]):
                candidate_feature_cols.append(col)
            else:
                print(f"Warning: Excluding non-numeric column '{col}' from features")
    
    if len(candidate_feature_cols) == 0:
        raise ValueError("No numeric feature columns found!")

    # Detect and drop "leaky" columns that basically duplicate the label
    leaky_cols = []
    if set(np.unique(y)) <= {0, 1}:
        y_bin = y.astype(int)
        for col in candidate_feature_cols:
            col_vals = df[col].values
            # skip all-NaN or constant columns
            if pd.isna(col_vals).all() or len(np.unique(col_vals)) == 1:
                continue

            # Only check low-cardinality columns for leakage (e.g., flags/IDs)
            if len(np.unique(col_vals)) <= 10:
                try:
                    match_direct = np.mean(col_vals == y_bin)
                    match_inverse = np.mean(col_vals == 1 - y_bin)
                except Exception:
                    continue

                if max(match_direct, match_inverse) > 0.99:
                    leaky_cols.append(col)

    if leaky_cols:
        print("\n⚠️  Potential label leakage detected!")
        print("   The following columns match the label almost perfectly (>99%) and will be excluded:")
        for c in leaky_cols:
            print(f"   - {c}")
        feature_cols = [c for c in candidate_feature_cols if c not in leaky_cols]
    else:
        feature_cols = candidate_feature_cols

    if len(feature_cols) == 0:
        raise ValueError("All numeric feature columns were excluded (possibly due to leakage).")

    print(f"\nUsing {len(feature_cols)} feature columns for training.")
    X = df[feature_cols].values
    
    return X, y, feature_cols


def train_model(X_train, y_train, X_test, y_test, feature_names):
    """
    Train Logistic Regression classifier.
    
    Args:
        X_train: Training features
        y_train: Training labels
        X_test: Test features
        y_test: Test labels
        feature_names: List of feature names
        
    Returns:
        Trained model, scaler, metrics dictionary, feature_importance DataFrame
    """
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train model
    print("Training Logistic Regression classifier...")
    model = LogisticRegression(
        penalty="l2",
        solver="liblinear",
        max_iter=1000,
        class_weight="balanced",
        random_state=config.RANDOM_STATE
    )
    model.fit(X_train_scaled, y_train)
    
    # Evaluate on test set
    y_pred = model.predict(X_test_scaled)
    
    # Predict probabilities (binary classification)
    y_pred_proba_full = model.predict_proba(X_test_scaled)
    if y_pred_proba_full.shape[1] == 2:
        y_pred_proba = y_pred_proba_full[:, 1]
    else:
        # Fallback, though LogisticRegression should require 2 classes to fit
        y_pred_proba = y_pred_proba_full[:, 0]
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    
    # AUC requires at least 2 classes
    if len(np.unique(y_test)) > 1:
        auc = roc_auc_score(y_test, y_pred_proba)
    else:
        auc = 0.0
        print("Warning: Only one class in test set, cannot calculate AUC-ROC")
    
    print(f"\nTest Set Performance:")
    print(f"  Accuracy: {accuracy:.4f}")
    print(f"  AUC-ROC: {auc:.4f}")
    print("\nClassification Report:")
    
    # Handle case where test set has only one class
    unique_test_classes = np.unique(y_test)
    if len(unique_test_classes) == 2:
        print(classification_report(y_test, y_pred, target_names=['Benign', 'Malware']))
    else:
        class_name = 'Benign' if unique_test_classes[0] == 0 else 'Malware'
        print(f"  Test set contains only {class_name} samples")
        print(f"  All {len(y_test)} test samples predicted as: {class_name}")
        print(f"  Accuracy: {accuracy:.4f}")
    
    # Cross-validation (only if we have multiple classes)
    if len(np.unique(y_train)) > 1:
        print("\nPerforming cross-validation...")
        cv = StratifiedKFold(n_splits=config.CV_FOLDS, shuffle=True, random_state=config.RANDOM_STATE)
        cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=cv, scoring='roc_auc')
        print(f"CV AUC-ROC: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    else:
        print("\nSkipping cross-validation (only one class in training data)")
        cv_scores = np.array([0.0])
    
    # Feature importance from Logistic Regression coefficients
    # Use absolute value of coefficients as importance
    if hasattr(model, "coef_"):
        coef = model.coef_
        if coef.ndim == 2 and coef.shape[0] == 1:
            coef = coef[0]
        importance_values = np.abs(coef)
    else:
        importance_values = np.zeros(len(feature_names))
    
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': importance_values
    }).sort_values('importance', ascending=False)
    
    metrics = {
        'accuracy': float(accuracy),
        'auc_roc': float(auc),
        'cv_auc_mean': float(cv_scores.mean()),
        'cv_auc_std': float(cv_scores.std()),
        'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
        'top_features': feature_importance.head(20).to_dict('records')
    }
    
    return model, scaler, metrics, feature_importance


def plot_results(y_test, y_pred, y_pred_proba, output_dir, feature_importance=None):
    """
    Plot ROC curve, confusion matrix, and accuracy metrics.
    
    Args:
        y_test: True labels
        y_pred: Predicted labels
        y_pred_proba: Predicted probabilities
        output_dir: Directory to save plots
        feature_importance: DataFrame with feature importance (optional)
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Create figure with subplots
    fig = plt.figure(figsize=(12, 5))
    
    # 1. Confusion Matrix
    ax1 = plt.subplot(1, 2, 1)
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax1,
                xticklabels=['Benign', 'Malware'],
                yticklabels=['Benign', 'Malware'])
    ax1.set_xlabel('Predicted')
    ax1.set_ylabel('Actual')
    ax1.set_title('Confusion Matrix')
    
    # 2. ROC Curve
    if len(np.unique(y_test)) > 1:
        ax2 = plt.subplot(1, 2, 2)
        fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
        auc_score = roc_auc_score(y_test, y_pred_proba)
        ax2.plot(fpr, tpr, label=f'ROC curve (AUC = {auc_score:.3f})')
        ax2.plot([0, 1], [0, 1], 'k--', label='Random')
        ax2.set_xlabel('False Positive Rate')
        ax2.set_ylabel('True Positive Rate')
        ax2.set_title('ROC Curve')
        ax2.legend()
        ax2.grid(True)
    else:
        ax2 = plt.subplot(1, 2, 2)
        ax2.text(0.5, 0.5, 'ROC curve not available\n(only one class in test set)',
                ha='center', va='center', transform=ax2.transAxes)
        ax2.set_title('ROC Curve')
    
    plt.tight_layout()
    plt.savefig(output_path / 'model_performance.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Saved performance visualization to {output_path / 'model_performance.png'}")
    
    # Create feature importance visualization
    if feature_importance is not None and len(feature_importance) > 0:
        plt.figure(figsize=(10, 8))
        top_features = feature_importance.head(15)  # Top 15 features
        plt.barh(range(len(top_features)), top_features['importance'].values)
        plt.yticks(range(len(top_features)), top_features['feature'].values)
        plt.xlabel('Importance (|coefficient|)')
        plt.title('Top 15 Most Important Features (Logistic Regression)')
        plt.gca().invert_yaxis()
        plt.tight_layout()
        plt.savefig(output_path / 'feature_importance.png', dpi=300, bbox_inches='tight')
        plt.close()
        print(f"Saved feature importance plot to {output_path / 'feature_importance.png'}")
    
    # Also save ROC curve separately if available
    if len(np.unique(y_test)) > 1:
        plt.figure(figsize=(8, 6))
        fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
        auc_score = roc_auc_score(y_test, y_pred_proba)
        plt.plot(fpr, tpr, label=f'ROC curve (AUC = {auc_score:.3f})')
        plt.plot([0, 1], [0, 1], 'k--', label='Random')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curve')
        plt.legend()
        plt.grid(True)
        plt.savefig(output_path / 'roc_curve.png', dpi=300, bbox_inches='tight')
        plt.close()
        print(f"Saved ROC curve to {output_path / 'roc_curve.png'}")


def main():
    parser = argparse.ArgumentParser(
        description="Train ML model for network traffic classification (Logistic Regression)"
    )
    parser.add_argument(
        '--features',
        type=str,
        default=str(config.FEATURES_DIR / "features.csv"),
        help='Path to features CSV file'
    )
    parser.add_argument(
        '--output',
        type=str,
        default=str(config.MODELS_DIR),
        help='Output directory for trained model'
    )
    parser.add_argument(
        '--test-size',
        type=float,
        default=config.TEST_SIZE,
        help='Test set size (default: 0.2)'
    )
    
    args = parser.parse_args()
    
    # Load features
    print(f"Loading features from {args.features}...")
    df = load_features(args.features)
    print(f"Loaded {len(df)} samples")
    
    # Prepare data
    X, y, feature_names = prepare_data(df)
    print(f"Number of features: {len(feature_names)}")
    print(f"Class distribution:")
    print(f"  Benign: {(y == 0).sum()}")
    print(f"  Malware: {(y == 1).sum()}")
    
    # Create class distribution visualization
    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)
    
    plt.figure(figsize=(8, 6))
    class_counts = pd.Series(y).value_counts().sort_index()
    labels = ['Benign', 'Malware']
    colors = ['#2ecc71', '#e74c3c']
    bars = plt.bar(labels, [class_counts.get(0, 0), class_counts.get(1, 0)], color=colors, alpha=0.7)
    plt.ylabel('Number of Samples')
    plt.title('Dataset Class Distribution')
    plt.grid(True, alpha=0.3, axis='y')
    
    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}',
                ha='center', va='bottom', fontsize=12, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(output_path / 'class_distribution.png', dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved class distribution plot to {output_path / 'class_distribution.png'}")
    
    # Check if we have both classes
    unique_classes = np.unique(y)
    if len(unique_classes) == 1:
        print("\n⚠️  WARNING: Only one class in dataset!")
        print("   Cannot train a binary classifier without both benign and malware samples.")
        print("   Please check:")
        print("   1. Your CSV files contain IP addresses")
        print("   2. The IP addresses in CSV files match those in the ground truth file")
        print("   3. The matching logic in extract_features_from_csv.py")
        return
    
    # Always perform a proper train/test split
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=args.test_size,
            random_state=config.RANDOM_STATE,
            stratify=y
        )
    except ValueError as e:
        print("\n❌ Error during train/test split:")
        print(f"   {e}")
        print("   This usually happens when there are too few samples per class for stratified splitting.")
        print("   Consider collecting more data or adjusting the test_size.")
        return
    
    print(f"\nTrain/Test split summary:")
    print(f"  Train samples: {len(X_train)} (Benign={(y_train == 0).sum()}, Malware={(y_train == 1).sum()})")
    print(f"  Test samples:  {len(X_test)} (Benign={(y_test == 0).sum()}, Malware={(y_test == 1).sum()})")
    
    # Train model
    model, scaler, metrics, feature_importance = train_model(
        X_train, y_train, X_test, y_test, feature_names
    )
    
    # Save model and scaler
    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)
    
    model_file = output_path / "model.pkl"
    scaler_file = output_path / "scaler.pkl"
    feature_names_file = output_path / "feature_names.json"
    metrics_file = output_path / "metrics.json"
    importance_file = output_path / "feature_importance.csv"
    
    dump(model, model_file)
    dump(scaler, scaler_file)
    
    with open(feature_names_file, 'w') as f:
        json.dump(feature_names, f)
    
    with open(metrics_file, 'w') as f:
        json.dump(metrics, f, indent=2)
    
    feature_importance.to_csv(importance_file, index=False)
    
    print(f"\nSaved model to {model_file}")
    print(f"Saved scaler to {scaler_file}")
    print(f"Saved feature names to {feature_names_file}")
    print(f"Saved metrics to {metrics_file}")
    print(f"Saved feature importance to {importance_file}")
    
    # Plot results (only if we have multiple classes)
    # Get predictions for visualization
    y_pred = model.predict(scaler.transform(X_test))
    if len(np.unique(y_test)) > 1:
        y_pred_proba_full = model.predict_proba(scaler.transform(X_test))
        if y_pred_proba_full.shape[1] == 2:
            y_pred_proba = y_pred_proba_full[:, 1]
        else:
            y_pred_proba = y_pred_proba_full[:, 0]
    else:
        y_pred_proba = np.zeros(len(y_test))
    
    plot_results(y_test, y_pred, y_pred_proba, output_path, feature_importance)
    
    # Print top features
    print("\nTop 10 Most Important Features (by |coefficient|):")
    for idx, row in feature_importance.head(10).iterrows():
        print(f"  {row['feature']}: {row['importance']:.4f}")
    
    print(f"\nAll visualizations saved to {output_path}/")
    print(f"  - model_performance.png (Confusion Matrix + ROC Curve)")
    print(f"  - feature_importance.png (Top 15 Features)")
    print(f"  - class_distribution.png (Dataset Balance)")
    print(f"  - roc_curve.png (ROC Curve standalone)")


if __name__ == "__main__":
    main()
