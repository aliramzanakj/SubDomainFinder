# Subdomain Finder - By Ali Ramzan

## Overview
This is a PyQt5-based desktop application designed to find alive subdomains for a specified domain using VirusTotal's API. It fetches a list of subdomains, checks which ones are accessible, and displays the results in an easy-to-use graphical interface. Users can then copy or save the list of alive subdomains for further use.

## Features
- Fetches subdomains for a given domain via VirusTotal API.
- Checks which subdomains are alive by sending HTTP requests.
- Displays results in a clear, organized text area.
- Copy or save alive subdomains to a file directly from the interface.

## Requirements
- Python 3.x
- PyQt5
- Requests
- VirusTotal API key

## Installation
1. **Clone the repository:**
   ```bash
   git clone https://github.com/aliramzanakj/SubDomainFinder.git
   cd SubDomainFinder
2. **Run Program:**
   ```bash
      python main.py
