const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ||
  "http://127.0.0.1:8000";


function getErrorMessage(errorData) {
  if (!errorData) {
    return "The analysis request failed.";
  }

  if (typeof errorData.detail === "string") {
    return errorData.detail;
  }

  if (Array.isArray(errorData.detail)) {
    return errorData.detail
      .map((error) => error.msg)
      .join(", ");
  }

  return "The analysis request failed.";
}


async function handleResponse(response) {
  if (!response.ok) {
    const errorData = await response
      .json()
      .catch(() => null);

    throw new Error(getErrorMessage(errorData));
  }

  return response.json();
}


export async function analyzeUrl(url) {
  const response = await fetch(
    `${API_BASE_URL}/api/analyze/url`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url }),
    }
  );

  return handleResponse(response);
}


export async function analyzeEmail({
  sender,
  subject,
  body,
}) {
  const response = await fetch(
    `${API_BASE_URL}/api/analyze/email`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        sender,
        subject,
        body,
      }),
    }
  );

  return handleResponse(response);
}