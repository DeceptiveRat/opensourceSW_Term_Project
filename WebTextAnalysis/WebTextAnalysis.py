#python3
!pip install transformers requests beautifulsoup4 scikit-learn

import requests
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from transformers import pipeline

def fetch_text_from_url(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    paragraphs = [p.get_text() for p in soup.find_all('p')]
    return ' '.join(paragraphs)

def extract_keywords(text, top_n=10):
    vectorizer = TfidfVectorizer(stop_words='english')
    X = vectorizer.fit_transform([text])
    tfidf_scores = zip(vectorizer.get_feature_names_out(), X.toarray()[0])
    sorted_keywords = sorted(tfidf_scores, key=lambda x: x[1], reverse=True)
    return sorted_keywords[:top_n]

def summarize_text(text, max_length=200, min_length=50):
    summarizer = pipeline("summarization", model="facebook/bart-large-cnn")
    try:
      
        if len(text.split()) < min_length:
            return "Text is too short for summarization."
        summary = summarizer(text, max_length=max_length, min_length=min_length, do_sample=False)
        return summary[0]['summary_text']
    except Exception as e:
        return f"An error occurred during summarization: {e}"

if __name__ == "__main__":
    url = input("Enter the URL to analyze: ")
    text = fetch_text_from_url(url)

    print("\nGenerating summary...")
    summary = summarize_text(text, max_length=200, min_length=50)
    print("\nSummary:")
    print(summary)

    if len(text.strip()) > 0:
        keywords = extract_keywords(text, top_n=10)
        print("\nTop Keywords:")
        for word, score in keywords:
            print(f"{word}: {score:.4f}")
    else:
        print("\nNo text found on the page. Cannot extract keywords.")

    custom_keywords = input("\nEnter keywords to filter (comma-separated): ").split(',')
    custom_keywords = [kw.strip() for kw in custom_keywords]
    filtered_keywords = filter_keywords(keywords, custom_keywords)

    print("\nFiltered Keywords:")
    if filtered_keywords:
        for word, score in filtered_keywords:
            print(f"{word}: {score:.4f}")
        print("\nDone!")
    else:
        print("No matching keywords found.")
import re

def extract_sentences_with_keywords(text, keywords):
    sentences = re.split(r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?)\s', text) 
    matched_sentences = []
    for sentence in sentences:
        for keyword in keywords:
            if keyword.lower() in sentence.lower():
                matched_sentences.append(sentence.strip())
                break  
    return matched_sentences

if __name__ == "__main__":
    url = input("Enter the URL to analyze: ")
    text = fetch_text_from_url(url)

    print("\nGenerating summary...")
    summary = summarize_text(text, max_length=200, min_length=50)
    print("\nSummary:")
    print(summary)

    if len(text.strip()) > 0:
        keywords = extract_keywords(text, top_n=10)
        print("\nTop Keywords:")
        for word, score in keywords:
            print(f"{word}: {score:.4f}")
    else:
        print("\nNo text found on the page. Cannot extract keywords.")

    custom_keywords = input("\nEnter keywords to filter (comma-separated): ").split(',')
    custom_keywords = [kw.strip() for kw in custom_keywords]  
    filtered_keywords = filter_keywords(keywords, custom_keywords)

    print("\nFiltered Keywords:")
    if filtered_keywords:
        for word, score in filtered_keywords:
            print(f"{word}: {score:.4f}")

        print("\nExtracting sentences with filtered keywords...")
        sentences = extract_sentences_with_keywords(text, [word for word, _ in filtered_keywords])
        if sentences:
            for idx, sentence in enumerate(sentences, 1):
                print(f"{idx}. {sentence}")
        else:
            print("No sentences found with the filtered keywords.")
    else:
        print("No matching keywords found.")
