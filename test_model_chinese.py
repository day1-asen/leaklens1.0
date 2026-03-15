"""Test script for LFM2.5-1.2B-Thinking model with Chinese"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from leaklens import generate_text, get_lf_model

def test_chinese_model():
    """Test the LFM2.5-1.2B-Thinking model with Chinese"""
    print("Testing LFM2.5-1.2B-Thinking model with Chinese...")
    
    # Test Chinese prompt
    prompt = "解释什么是LeakLens以及它是如何工作的"
    
    try:
        # Generate response
        response = generate_text(prompt, max_length=300)
        print("\n中文响应:")
        print(response)
        print("\n测试成功!")
    except Exception as e:
        print(f"\n测试失败，错误: {e}")

if __name__ == "__main__":
    test_chinese_model()
