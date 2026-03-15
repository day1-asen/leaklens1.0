"""Test script for LFM2.5-1.2B-Thinking model"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from leaklens import generate_text, get_lf_model

def test_model():
    """Test the LFM2.5-1.2B-Thinking model"""
    print("Testing LFM2.5-1.2B-Thinking model...")
    
    # Test prompt
    prompt = "Explain what LeakLens is and how it works"
    
    try:
        # Generate response
        response = generate_text(prompt, max_length=200)
        print("\nResponse:")
        print(response)
        print("\nTest passed successfully!")
    except Exception as e:
        print(f"\nTest failed with error: {e}")

if __name__ == "__main__":
    test_model()
