Developed a local AI-based Security Operations Center (SOC) log analysis tool using Ollama and Streamlit to simulate Tier-2 analyst workflows in a real-world environment
Engineered a multi-format log ingestion pipeline supporting .csv, .log, .txt, and Windows .evtx files with robust handling for UTF-16 encoding, null bytes, and corrupted datasets
Implemented adaptive log preprocessing and truncation mechanisms to prevent LLM crashes and optimize performance for low-resource environments
Integrated LLM-driven threat detection to identify suspicious activities such as brute-force login attempts, anomalous authentication behavior, and potential account compromise
Designed an automated incident response generation system that outputs structured JSON including risk scoring, attack timeline reconstruction, root cause analysis, and containment playbooks
Built a resilient fallback parsing system to ensure continuous log analysis even when standard structured parsing fails, mimicking real-world SIEM ingestion strategies
Enabled offline-first security analysis, ensuring no sensitive log data leaves the system, aligning with privacy and enterprise security requirements
Developed an interactive dashboard for real-time visualization of security insights, including risk metrics, suspicious activity summaries, and downloadable incident reports
Implemented multi-model compatibility and fallback logic, allowing seamless switching between local LLMs (e.g., Gemma, LLaMA) for improved reliability
