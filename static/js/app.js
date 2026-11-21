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

        // Quick "Paste Sample Email" Button
        const loadSamplePasteBtn = document.getElementById('loadSamplePasteBtn');
        if (loadSamplePasteBtn) {
            loadSamplePasteBtn.addEventListener('click', () => {
                const sampleRaw = `From: security-alerts@example.com\r\nTo: user@recipient.org\r\nSubject: Monthly Security Audit Notification\r\nDate: Mon, 26 Oct 2026 10:00:00 +0000\r\nMessage-ID: <audit-2026-1026@example.com>\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=example.com;\r\n i=@example.com; q=dns/txt; s=cns2026; t=1793019143; h=from : to :\r\n subject : date : message-id : content-type : from;\r\n bh=0zBMp+S3qwQAkNo7Y6zTgg4X7WYLArbCamQVSQcw3lQ=;\r\n b=sZ+pl5+bi0440aTKnrM953IALNLY2u+673sO0IFlP3cNE3RZJOCVLMw+ga72uY64mhkN8\r\n 6ecenV2bGCrbqV64Km5R2+dkXjOQa4vIryPwtgnj6gIBjeKbLzu9GsVAxTRb7nmzO5TDhtP\r\n wnxZ0kIsGncMlS/8tVSqee9USSQyDYur1juXBtPMRw2dbbuTvEZNGkQaNsQVi3qVOOuN7jU\r\n oA0tqEZyERBqN8eWFmtlG5LiQPfLBNRobcQCRl9qRm2y2a3d5cej3AAJz2vKF+25R2HuS5m\r\n QTA3H/G30cNbcRtcbIWKfdbQepDsb7me4roFFoX2xQLUaZyaLCWJ4hxG/WOw==\r\nReturn-Path: <security-alerts@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello Admin,\r\n\r\nThis is a routine monthly security notification from Example Corp.\r\nYour system integrity checks have passed with no vulnerabilities detected.\r\n\r\nRegards,\r\nSecurity Operations Center`;
                rawEmailText.value = sampleRaw;
                if (charCount) charCount.textContent = `${sampleRaw.length.toLocaleString()} characters`;
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

    // 4. Initialize Bootstrap 5 Tooltips
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    [...tooltipTriggerList].forEach(el => {
        new bootstrap.Tooltip(el);
    });

    // 5. Global Copy-to-Clipboard Handler
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const textToCopy = btn.getAttribute('data-copy') || '';
            if (!textToCopy) return;

            navigator.clipboard.writeText(textToCopy).then(() => {
                const origHtml = btn.innerHTML;
                btn.innerHTML = '<i class="bi bi-check2 text-success"></i> Copied!';
                setTimeout(() => {
                    btn.innerHTML = origHtml;
                }, 1800);
            }).catch(err => {
                console.error('Clipboard copy error:', err);
            });
        });
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    // Initial state check
    updateAnalyzeButtonState();
});
