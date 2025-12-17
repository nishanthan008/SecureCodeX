# How to Upload SecureCodeX to GitHub

Since git was not detected in your command line, follow these steps to install Git and upload your code.

## Step 1: Install Git

1.  Download Git for Windows: [https://git-scm.com/download/win](https://git-scm.com/download/win)
2.  Run the installer. **Important**: during installation, check the option "Add Git to command line path" or "Use Git from the Windows Command Prompt".
3.  After installation, restart your terminal/VS Code.
4.  Verify installation by running:
    ```bash
    git --version
    ```

## Step 2: Create a Repository on GitHub

1.  Log in to your [GitHub account](https://github.com/).
2.  Click the **+** icon in the top-right corner and select **New repository**.
3.  Enter a name (e.g., `SecureCodeX`).
4.  Choose **Public** or **Private**.
5.  Do **NOT** check "Initialize this repository with a README" (you already have one).
6.  Click **Create repository**.
7.  Copy the URL (e.g., `https://github.com/YourUsername/SecureCodeX.git`).

## Step 3: Initialize and Upload (in your terminal)

Open your terminal in `c:\Code\SecureCodeX-CLI` and run these commands one by one:

1.  **Initialize Git:**
    ```bash
    git init
    ```

2.  **Add all files:**
    ```bash
    git add .
    ```

3.  **Commit the files:**
    ```bash
    git commit -m "Initial commit of SecureCodeX CLI tool"
    ```

4.  **Rename branch to main:**
    ```bash
    git branch -M main
    ```

5.  **Link to your GitHub repo:** (Replace URL with yours)
    ```bash
    git remote add origin https://github.com/YourUsername/SecureCodeX.git
    ```

6.  **Push the code:**
    ```bash
    git push -u origin main
    ```

## Step 4: Installation for Others

Once uploaded, anyone can install your tool using:

```bash
pip install git+https://github.com/YourUsername/SecureCodeX.git
```
