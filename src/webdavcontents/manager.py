from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, List, Optional, Union
import base64
import io
from pathlib import Path

from jupyter_server import _tz as tz
from jupyter_server.services.contents.manager import ContentsManager
from jupyter_server.services.contents.fileio import FileManagerMixin
from tornado import web
from traitlets import Unicode
from webdav4.client import Client
import webdav4


@dataclass
class WebdavFile:
    name: str
    path: str
    type: str
    last_modified: datetime
    created: datetime
    mimetype: Optional[str]
    size: Optional[int]
    content: Union[str, List[Any], None] = None
    format: Optional[str] = None
    writable: Optional[bool] = None
    hash: Optional[str] = None
    hash_algorithm: Optional[str] = None


class WebdavContentsManager(FileManagerMixin, ContentsManager):

    base_url = Unicode(
        "",
        help="WebDAV base URL",
    ).tag(config=True, env="JPYNB_WEBDAV_BASE_URL")

    user_id = Unicode(
        help="WebDAV user ID",
        allow_none=True,
        default_value=None,
    ).tag(config=True, env="JPYNB_WEBDAV_USER_ID")
    
    password = Unicode(
        help="WebDAV password",
        allow_none=True,
        default_value=None,
    ).tag(config=True, env="JPYNB_WEBDAV_PASSWORD")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._client = Client(self.base_url, auth=(self.user_id, self.password))
    
    def get(self, path, content=True, type=None, format=None, require_hash=False):
        """Takes a path for an entity and returns its model

        Parameters
        ----------
        path : str
            the API path that describes the relative path for the target
        content : bool
            Whether to include the contents in the reply
        type : str, optional
            The requested type - 'file', 'notebook', or 'directory'.
            Will raise HTTPError 400 if the content doesn't match.
        format : str, optional
            The requested format for file contents. 'text' or 'base64'.
            Ignored if this returns a notebook or directory model.
        require_hash: bool, optional
            Whether to include the hash of the file contents.

        Returns
        -------
        model : dict
            the contents model. If content=True, returns the contents
            of the file or directory as well.
        """
        four_o_four = "file or directory does not exist: %r" % path

        try:
            info = self._client.info(path)
        except webdav4.client.ResourceNotFound as exc:
            raise web.HTTPError(404, four_o_four) from exc

        model_type = info["type"]
        if model_type == "file" and info["display_name"].endswith(".ipynb"):
            model_type = "notebook"
        model = WebdavFile(
            name=info["display_name"],
            path=info["name"],
            type=model_type,
            created=info["created"] or datetime(1970, 1, 1, 0, 0, tzinfo=tz.UTC),
            last_modified=info["modified"] or datetime(1970, 1, 1, 0, 0, tzinfo=tz.UTC),
            mimetype=info["content_type"],
            size=info["content_length"],
        )

        def fill_content(model, format, require_hash):
            if model.type == "directory":
                model.format = "json"
                model.content = []
                for info in self._client.ls(model.path):
                    entry = WebdavFile(
                        name=info["display_name"],
                        path=info["name"],
                        type=info["type"],
                        created=info["created"] or datetime(1970, 1, 1, 0, 0, tzinfo=tz.UTC),
                        last_modified=info["modified"] or datetime(1970, 1, 1, 0, 0, tzinfo=tz.UTC),
                        mimetype=info["content_type"],
                        size=info["content_length"],
                    )
                    entry = fill_content(entry, None, require_hash)
                    model.content.append(entry)
            else:  # model type is file or notebook
                if not format:
                    if model.type == "file":
                        if model.mimetype.startswith("text/plain"):
                            format = "text"
                        elif model.mimetype.startswith("application/octet-stream"):
                            format = "base64"
                    elif model.type == "notebook":
                        format = "json"
                model.format = format
                buf = io.BytesIO()
                self._client.download_fileobj(model.path, buf)
                bytes_content = buf.getvalue() or b""
                if model.format == "text" or model.format == "json":
                    model.content = bytes_content.decode("utf-8")
                elif model.format == "base64":
                    model.content = base64.b64encode(bytes_content).decode("ascii")
                if require_hash:
                    hash_info = self._get_hash(bytes_content)
                    model.hash = hash_info["hash"]
                    model.hash_algorithm = hash_info["hash_algorithm"]
            return model

        if content:
            model = fill_content(model, format, require_hash)

        self.emit(data={"action": "get", "path": path})
        return asdict(model)

    def save(self, model_asdict, path):
        model = WebdavFile(**model_asdict)
        raise NotImplementedError
    
    def delete_file(self, path):
        """Delete file at path."""

        if not self.allow_hidden and self.is_hidden(path):
            raise web.HTTPError(400, f"Cannot delete file or directory {path!r}")

        four_o_four = "file or directory does not exist: %r" % path

        try:
            self._client.remove(path)
        except Exception as exc:
            raise web.HTTPError(400, f"Cannot delete file or directory {path!r}") from exc

    def rename_file(self, old_path, new_path):
        """Rename a file."""
        if new_path == old_path:
            return


        if not self.allow_hidden and (
            self.is_hidden(old_path) or self.is_hidden(new_path)
        ):
            raise web.HTTPError(400, f"Cannot rename file or directory {old_path!r}")

        try:
            self._client.move(old_path, new_path)
        except Exception as exc:
            raise web.HTTPError(500, f"Unknown error renaming file: {old_path!r}") from exc

    def file_exists(self, path):
        """Returns True if the file exists, else returns False.

        API-style wrapper for os.path.isfile

        Parameters
        ----------
        path : str
            The relative path to the file (with '/' as separator)

        Returns
        -------
        exists : bool
            Whether the file exists.
        """
        try:
            return self._client.isfile(path)
        except webdav4.client.ResourceNotFound:
            return False

    def dir_exists(self, path):
        """Does the API-style path refer to an extant directory?

        API-style wrapper for os.path.isdir

        Parameters
        ----------
        path : str
            The path to check. This is an API path (`/` separated,
            relative to root_dir).

        Returns
        -------
        exists : bool
            Whether the path is indeed a directory.
        """
        try:
            return self._client.isdir(path)
        except webdav4.client.ResourceNotFound:
            return False

    def is_hidden(self, path):
        """Does the API style path correspond to a hidden directory or file?

        Parameters
        ----------
        path : str
            The path to check. This is an API path (`/` separated,
            relative to root_dir).

        Returns
        -------
        hidden : bool
            Whether the path exists and is hidden.
        """
        if any(part.startswith(".") for part in Path(path).parts):
            return True
