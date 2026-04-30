# Homebrew formula for sidestep-a (alpha channel)
# Updated automatically by CI on every push to main.
# macOS arm64 only. Installs as `sidestep-a` so it can coexist with the
# stable `sidestep` formula on the same machine.

class SidestepA < Formula
  desc "Rust CLI for the StepSecurity API (alpha channel)"
  homepage "https://github.com/ArcavenAE/sidestep"
  version "TAG_PLACEHOLDER"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/ArcavenAE/sidestep/releases/download/TAG_PLACEHOLDER/sidestep-a-darwin-arm64"
    sha256 "SHA256_DARWIN_ARM64_PLACEHOLDER"
  else
    odie "sidestep-a currently only supports macOS arm64."
  end

  def install
    bin.install "sidestep-a-darwin-arm64" => "sidestep-a"
  end

  def caveats
    <<~EOS
      sidestep-a is the alpha channel. Updates on every push to main.
      For stable: brew install ArcavenAE/tap/sidestep (when first tagged).

      Bootstrap a token (recommended — uses macOS Keychain):

        sidestep-a auth login --token <bearer-token>
        sidestep-a auth status

      Then invoke any spec operation:

        sidestep-a ops list
        sidestep-a api <operationId> --param key=value
    EOS
  end

  test do
    assert_match "sidestep", shell_output("#{bin}/sidestep-a --version 2>&1")
  end
end
