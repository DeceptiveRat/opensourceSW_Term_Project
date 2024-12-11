# 4. WebTextAnalysis

## 4-1. Description

This is a web-based text analysis tool that crawls text from a webpage, extracts keywords using TF-IDF, summarizes the text using Hugging Face, and filters keywords based on user input. Additionally, it can extract sentences containing filtered keywords for further analysis.
(Features: Web Crawling, Keyword Extraction, Text Summarization, Custom Keyword Filtering, Sentence Extraction)

## 4-2. Requirments

The following Python packages are required to run the tool. They can be installed using pip:

- transformers (for Hugging Face summarization)
- requests (for making HTTP requests to fetch web pages)
- beautifulsoup4 (for parsing HTML and extracting text)
- scikit-learn (for TF-IDF-based keyword extraction)
Run the following command to install the necessary packages: !pip install transformers requests beautifulsoup4 scikit-learn

## 4-3. Usage

1. Clone or Download the Repository (To use this tool, clone the repository to your local machine)
2. Run the Script
RUN THE SCRIPT! The tool will prompt you to enter a URL of the webpage you want to analyze.
3. The tool will:
Summarize the text on the webpage.
Extract the top 10 keywords from the content.
Allow you to enter custom keywords for filtering the results.
Display sentences containing the filtered keywords!

## 4-4. Reference

- **Hugging Face Transformers**: https://huggingface.co/transformers/
- **BeautifulSoup Documentation**: https://www.crummy.com/software/BeautifulSoup/bs4/doc/
- **Scikit-learn Documentation**: https://scikit-learn.org/stable/
- **TF-IDF Vectorization**: [https://en.wikipedia.org/wiki/Tf–idf](https://en.wikipedia.org/wiki/Tf%E2%80%93idf)

## 4-5. License
This project is licensed under the MIT License - see the LICENSE file for details.

## 4-6. Examples
1. Put your URL that you want to analysis then tool will show the frequency of words
![image](https://github.com/user-attachments/assets/0840062b-662d-4931-afc3-1864bfa1a3f1)
2. You can select the words that you want to filter (seperated by comma)
![image](https://github.com/user-attachments/assets/608126f5-17d4-43a3-8bf0-da51417ebbfc)
3. Once again put your URL that you want to analysis
![image](https://github.com/user-attachments/assets/47a89010-e0c3-4fa9-bbdd-58f6a56357a6)
4. After tool analys URL, Tool will show keywords.
   When you choose some keywords, the tool will show the sentences in the URL. (Sentences that include the words that you choose!)
![image](https://github.com/user-attachments/assets/c048452f-014b-4463-a1be-b93e248450c5)
