/**
 * MailTrust Frontend Client Script
 * Handles drag-and-drop file ingestion, input validation, live counters,
 * and loading states to prevent duplicate submissions.
 */

document.addEventListener('DOMContentLoaded', () => {
    // Elements for Main Analysis Form
    const analysisForm = document.getElementById('analysisForm');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const btnText = document.getElementById('btnText');
    const btnSpinner = document.getElementById('btnSpinner');

    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('emailFileInput');
    const dropzoneEmpty = document.getElementById('dropzoneEmptyState');
    const dropzoneSelected = document.getElementById('dropzoneSelectedState');
    const selectedFileName = document.getElementById('selectedFileName');
    const selectedFileSize = document.getElementById('selectedFileSize');
    const removeFileBtn = document.getElementById('removeFileBtn');

    const rawEmailText = document.getElementById('rawEmailText');
    const clearTextBtn = document.getElementById('clearTextBtn');
    const charCount = document.getElementById('charCount');

    // Input state tracking
    function updateAnalyzeButtonState() {
        if (!analyzeBtn) return;
        const hasFile = fileInput && fileInput.files && fileInput.files.length > 0;
        const hasText = rawEmailText && rawEmailText.value.trim().length > 0;

        if (hasFile || hasText) {
            analyzeBtn.disabled = false;
        } else {
            analyzeBtn.disabled = true;
        }
    }

    // 1. File Upload Drag-and-Drop Handling
    if (dropZone && fileInput) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
        });

        dropZone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files && files.length > 0) {
                fileInput.files = files;
                renderSelectedFile(files[0]);
                updateAnalyzeButtonState();
            }
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files && fileInput.files.length > 0) {
                renderSelectedFile(fileInput.files[0]);
                updateAnalyzeButtonState();
            }
        });

        if (removeFileBtn) {
            removeFileBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                fileInput.value = '';
                dropzoneSelected.classList.add('d-none');
                dropzoneEmpty.classList.remove('d-none');
                updateAnalyzeButtonState();
            });
        }
    }

    function renderSelectedFile(file) {
        if (selectedFileName) selectedFileName.textContent = file.name;
        if (selectedFileSize) {
            const kb = (file.size / 1024).toFixed(1);
            selectedFileSize.textContent = `${kb} KB`;
        }
        if (dropzoneEmpty) dropzoneEmpty.classList.add('d-none');
        if (dropzoneSelected) dropzoneSelected.classList.remove('d-none');
    }

    // 2. Textarea Handling
    if (rawEmailText) {
        rawEmailText.addEventListener('input', () => {
            const len = rawEmailText.value.length;
            if (charCount) {
                charCount.textContent = `${len.toLocaleString()} characters`;
            }
            updateAnalyzeButtonState();
        });

        if (clearTextBtn) {
            clearTextBtn.addEventListener('click', () => {
                rawEmailText.value = '';
                if (charCount) charCount.textContent = '0 characters';
                updateAnalyzeButtonState();
            });
        }
    }

    // 3. Form Submit & Loading State (Prevents Duplicate Submissions)
    if (analysisForm) {
        analysisForm.addEventListener('submit', (e) => {
            if (analyzeBtn && !analyzeBtn.disabled) {
                analyzeBtn.disabled = true;
                if (btnSpinner) btnSpinner.classList.remove('d-none');
                if (btnText) btnText.innerHTML = 'Analyzing Authenticity...';
            }
        });
    }

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    // Initial state check
    updateAnalyzeButtonState();
});
