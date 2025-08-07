# Sift - Dependencies Setup

## Required Dependencies

### 1. Python Forensic Library (pytsk3)

Sift requires `pytsk3` for forensic image processing. Install it using one of these methods:

#### Option A: System Package (Recommended for Ubuntu/Debian)
```bash
sudo apt update
sudo apt install python3-pytsk3
```

#### Option B: PIP Install (if system packages not available)
```bash
pip install pytsk3
```

#### Option C: Virtual Environment (Recommended)
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Ollama (for LLM capabilities)

Sift uses local Ollama models for analysis:
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama serve
ollama pull gemma:7b  # Recommended starting model
```

### 3. Environment Configuration

Copy the example environment file and configure:
```bash
cp .env.example .env
# Edit .env with your API keys and settings
```

### 4. Additional Python Dependencies

Install all required packages:
```bash
pip install -r requirements.txt
```

The main dependencies include:
- **Flask**: Web interface framework
- **pytsk3**: Digital forensic disk image processing
- **tweepy**: Twitter API integration
- **praw**: Reddit API integration
- **ollama**: Local LLM integration
- **selenium**: Web scraping for dynamic content
- **plotly**: Interactive visualizations
- **folium**: Geographic mapping

## Testing the Installation

1. **Test Python Dependencies**:
```bash
python3 -c "import pytsk3, flask, ollama; print('Core dependencies available')"
```

2. **Test Ollama Integration**:
```bash
ollama list  # Should show available models
```

3. **Test with Sample Evidence**:
```bash
python3 debug_evidence.py
```

4. **Start the Application**:
```bash
cd src
python3 webapp.py
# Visit http://localhost:5000
```

## Common Issues

### Issue: "ModuleNotFoundError: No module named 'pytsk3'"
**Solution**: Install pytsk3 using one of the methods above.

### Issue: "Evidence file is too small"
**Solution**: The test files need to be valid filesystem images

### Issue: "No forensic events found"
**Solution**: The evidence file may not contain a valid filesystem or may be empty. Check that your evidence files are proper disk images with filesystems.