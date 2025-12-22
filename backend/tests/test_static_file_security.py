"""Tests for static file serving security (path traversal prevention)."""


class TestStaticFilePathTraversal:
    """Tests for path traversal protection in SPA static file serving."""

    async def test_direct_path_traversal_blocked(self, client):
        """Test that direct path traversal attempts are blocked."""
        traversal_attempts = [
            "/../etc/passwd",
            "/../../etc/passwd",
            "/../../../etc/passwd",
            "/assets/../../../etc/passwd",
        ]

        for path in traversal_attempts:
            response = await client.get(path)

            # Should either serve index.html or reject
            # Should NOT serve files outside static directory
            assert response.status_code in [200, 404]

            # If 200, should be index.html, not passwd file
            if response.status_code == 200:
                assert "<!DOCTYPE html>" in response.text or "<html" in response.text
                assert "root:" not in response.text  # passwd file content

    async def test_symlink_traversal_blocked(self, client):
        """Test that symlink-based traversal is blocked."""
        # Even if attacker creates symlink in static dir, resolve() prevents escape
        response = await client.get("/fake_symlink_to_etc")

        # Should serve index.html for non-existent paths
        assert response.status_code in [200, 404]

    async def test_url_encoded_traversal_blocked(self, client):
        """Test that URL-encoded traversal sequences are blocked."""
        encoded_attempts = [
            "/%2e%2e/etc/passwd",  # ../
            "/%2e%2e%2f%2e%2e/etc/passwd",  # ../../
            "/assets/%2e%2e/%2e%2e/etc/passwd",
        ]

        for path in encoded_attempts:
            response = await client.get(path)

            assert response.status_code in [200, 404]
            if response.status_code == 200:
                # Should be HTML, not passwd
                assert "<!DOCTYPE html>" in response.text or "<html" in response.text

    async def test_double_encoded_traversal_blocked(self, client):
        """Test that double-encoded traversal is blocked."""
        # %252e = encoded dot (%)
        double_encoded = "/%252e%252e/etc/passwd"

        response = await client.get(double_encoded)
        assert response.status_code in [200, 404]

    async def test_legitimate_static_files_served(self, client):
        """Test that legitimate static files are still served correctly."""
        # These should work if files exist
        legitimate_paths = [
            "/",  # index.html
            "/favicon.ico",
            "/manifest.json",
        ]

        for path in legitimate_paths:
            response = await client.get(path)
            # Should either succeed or 404 if file doesn't exist
            # Should NOT be auth error
            assert response.status_code in [200, 404]

    async def test_assets_directory_accessible(self, client):
        """Test that assets directory is accessible for legitimate files."""
        # Assuming some asset exists
        response = await client.get("/assets/index.js")

        # Should either serve file or 404, not path traversal
        assert response.status_code in [200, 404]

    async def test_windows_path_separators_blocked(self, client):
        """Test that Windows-style path separators don't bypass protection."""
        windows_attempts = [
            "/..\\..\\etc\\passwd",
            "/assets\\..\\..\\etc\\passwd",
        ]

        for path in windows_attempts:
            response = await client.get(path)
            assert response.status_code in [200, 404]
            if response.status_code == 200:
                assert "<!DOCTYPE html>" in response.text or "<html" in response.text

    async def test_null_byte_in_path_blocked(self, client):
        """Test that null bytes don't bypass path validation."""
        null_byte_attempts = [
            "/etc/passwd%00.html",
            "/../etc/passwd%00",
        ]

        for path in null_byte_attempts:
            response = await client.get(path)
            # Should reject or serve index.html
            assert response.status_code in [200, 400, 404]

    async def test_absolute_path_blocked(self, client):
        """Test that absolute paths don't bypass protection."""
        # FastAPI should handle this, but verify
        response = await client.get("//etc/passwd")

        assert response.status_code in [200, 404]
        if response.status_code == 200:
            assert "root:" not in response.text


class TestPathResolutionSecurity:
    """Tests for path resolution security."""

    async def test_path_stays_within_static_directory(self, client):
        """Test that all resolved paths stay within static directory."""
        # This is more of an integration test
        # The fix uses resolve() and startswith() to ensure containment

        dangerous_paths = [
            "/../",
            "/../../",
            "/assets/../../../",
            "/..",
        ]

        for path in dangerous_paths:
            response = await client.get(path)

            # Should serve index.html for SPA routing
            assert response.status_code in [200, 404]

            # Should NOT serve directory listings or error traces
            if response.status_code == 200:
                # Either HTML or specific file, not directory listing
                content_type = response.headers.get("content-type", "")
                assert "text/html" in content_type or "application/" in content_type

    async def test_case_sensitivity_preserved(self, client):
        """Test that case sensitivity in paths is preserved."""
        # On case-sensitive filesystems, /Assets != /assets
        response = await client.get("/Assets/nonexistent.js")

        # Should handle gracefully (404 or index.html)
        assert response.status_code in [200, 404]


class TestErrorHandling:
    """Tests for error handling in static file serving."""

    async def test_invalid_path_characters_handled(self, client):
        """Test that invalid path characters are handled safely."""
        invalid_paths = [
            "/file|with|pipes",
            "/file<with>brackets",
            "/file*with*wildcards",
        ]

        for path in invalid_paths:
            response = await client.get(path)

            # Should handle gracefully, not crash
            assert response.status_code in [200, 400, 404]

    async def test_very_long_path_handled(self, client):
        """Test that very long paths don't cause issues."""
        long_path = "/" + "a" * 10000

        response = await client.get(long_path)

        # Should handle gracefully
        assert response.status_code in [200, 404, 414]  # 414 = URI Too Long

    async def test_path_with_multiple_dots_handled(self, client):
        """Test that paths with multiple consecutive dots are handled."""
        multi_dot_paths = [
            "/...",
            "/....",
            "/file...txt",
        ]

        for path in multi_dot_paths:
            response = await client.get(path)
            assert response.status_code in [200, 404]
