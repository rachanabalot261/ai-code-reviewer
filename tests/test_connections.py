import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dotenv import load_dotenv
from google import genai
from groq import Groq

# Loads environmental variables for other components like Groq
load_dotenv()

def test_gemini():
    print("Testing Google Gemini connection...")
    try:
        # HARDCODE CURE: Your Gemini key is pasted directly here
        client = genai.Client(api_key="gemini key")
        
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents="Reply with exactly: OK",
        )
        text = response.text.strip() if response.text else "BLOCKED"
        assert "OK" in text, f"Unexpected response: {text}"
        print(f"  ✅ Gemini 2.5 Flash: {text}")
    except Exception as e:
        print(f"  ❌ Gemini Connection Failed: {e}")
        raise

def test_groq():
    print("Testing Groq Llama connection...")
    try:
        # Kept exactly as original: loads from your .env file
        client = Groq(api_key=os.environ["GROQ_API_KEY"])
        resp = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            max_tokens=10,
            messages=[{"role": "user", "content": "Reply with exactly: OK"}],
        )
        text = resp.choices[0].message.content.strip()
        print(f"  ✅ Groq Llama: {text}")
    except Exception as e:
        print(f"  ❌ Groq Connection Failed: {e}")
        raise

if __name__ == "__main__":
    print("Testing API connections...")
    test_gemini()
    test_groq()
    print("\n✅ Both APIs connected. Proceed to Step 5.")