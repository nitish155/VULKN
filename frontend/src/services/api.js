

export const triggerAiScan = async (targetUrl) => {
    const response = await fetch('http://10.220.216.228:8000/api/ai/analyze', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        // We send the URL the user typed in as the 'target'
        body: JSON.stringify({ target: targetUrl })
    });

    if (!response.ok) {
        throw new Error(`Backend Error: ${response.status}`);
    }

    // Convert the response into JSON data we can use in the UI
    return await response.json();
};