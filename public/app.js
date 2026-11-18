const signedOut = document.querySelector("#signed-out-view");
const signedIn = document.querySelector("#signed-in-view");
const errorBox = document.querySelector("#error-message");
const profileForm = document.querySelector("#profile-form");
const displayNameInput = document.querySelector("#display-name");
const bioInput = document.querySelector("#profile-bio");
const saveButton = document.querySelector("#save-profile-button");
const saveStatus = document.querySelector("#profile-save-status");
const storageNote = document.querySelector("#profile-storage-note");

document.querySelector("#year").textContent = new Date().getFullYear();

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

function updateBioCount() {
  document.querySelector("#bio-count").textContent = `${bioInput.value.length} / 240`;
}

async function loadSession() {
  try {
    const response = await fetch("/api/me", {
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    });

    if (response.status === 401) {
      if (window.location.pathname === "/dashboard") window.location.replace("/");
      return;
    }
    if (!response.ok) throw new Error("Session lookup failed");

    const result = await response.json();
    if (!result.authenticated || !result.user) {
      window.location.replace("/");
      return;
    }

    const user = result.user;
    signedOut.hidden = true;
    signedIn.hidden = false;

    document.querySelector("#welcome-title").textContent = `Welcome, ${user.displayName.split(" ")[0]}.`;
    document.querySelector("#profile-name").textContent = user.displayName;
    document.querySelector("#profile-email").textContent = user.email || "Email not provided";
    displayNameInput.value = user.displayName;
    bioInput.value = user.bio || "";
    updateBioCount();

    const verifiedMark = document.querySelector("#verified-mark");
    verifiedMark.textContent = user.emailVerified ? "✓" : "•";
    verifiedMark.title = user.emailVerified ? "Email verified" : "Email not verified";

    if (user.picture) {
      const image = document.querySelector("#profile-picture");
      image.src = user.picture;
      image.hidden = false;
      document.querySelector("#profile-fallback").hidden = true;
    }

    if (!user.profileEditable) {
      displayNameInput.disabled = true;
      bioInput.disabled = true;
      saveButton.disabled = true;
      storageNote.hidden = false;
    }
  } catch {
    showError("We couldn't load your account. Refresh the page and try again.");
  }
}

bioInput?.addEventListener("input", updateBioCount);

profileForm?.addEventListener("submit", async event => {
  event.preventDefault();
  saveButton.disabled = true;
  saveButton.querySelector("span").textContent = "Saving…";
  saveStatus.textContent = "";

  try {
    const response = await fetch("/api/me/profile", {
      method: "PUT",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        displayName: displayNameInput.value,
        bio: bioInput.value
      })
    });
    const result = await response.json();

    if (!response.ok) throw new Error(result.error || "Couldn't save your profile.");

    document.querySelector("#welcome-title").textContent = `Welcome, ${result.displayName.split(" ")[0]}.`;
    document.querySelector("#profile-name").textContent = result.displayName;
    saveStatus.textContent = "Your profile has been saved.";
    saveStatus.className = "save-status success";
  } catch (error) {
    saveStatus.textContent = error.message || "Couldn't save your profile. Try again.";
    saveStatus.className = "save-status error";
  } finally {
    saveButton.disabled = false;
    saveButton.querySelector("span").textContent = "Save changes";
  }
});

document.querySelector("#sign-out-button")?.addEventListener("click", async event => {
  const button = event.currentTarget;
  button.disabled = true;
  button.textContent = "Signing out…";
  try {
    const response = await fetch("/auth/logout", {
      method: "POST",
      credentials: "same-origin"
    });
    if (!response.ok) throw new Error("Sign-out failed");
    window.location.assign("/");
  } catch {
    button.disabled = false;
    button.textContent = "Sign out";
    showError("We couldn't sign you out. Please try again.");
  }
});

loadSession();
