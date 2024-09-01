from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import base64
import hashlib
import io

import nbformat
from jupyter_server import _tz as tz
from jupyter_server.services.contents.manager import ContentsManager
from jupyter_server.services.contents.filecheckpoints import GenericFileCheckpoints
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


class WebdavContentsManager(ContentsManager):

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

    root_dir = Unicode(
        help="WebDAV local root directory for the checkpoint",
        allow_none=False,
        default_value="./",
    ).tag(config=True, env="JPYNB_WEBDAV_LOCAL_CHECKPOINT_ROOT_DIR")

    hash_algorithm = Unicode(
        help="WebDAV hash algorithm",
        allow_none=False,
        default_value="sha256",
    ).tag(config=True, env="JPYNB_WEBDAV_HASH_ALGORITHM")

    def _checkpoints_class_default(self):
        return GenericFileCheckpoints

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._client = Client(self.base_url, auth=(self.user_id, self.password))

    @staticmethod
    def _convert_to_notebook(model: WebdavFile, as_version: int = 4, capture_validation_error: bool = None) -> WebdavFile:
        """Convert the content of a text file to the notebook content."""

        assert model.format == "json"
        try:
            model.content = nbformat.reads(
                model.content,
                as_version=as_version,
                capture_validation_error=capture_validation_error,
            )
            return model
        except Exception as exc:
            raise web.HTTPError(400, f"Unreadable Notebook: {model.path!r}") from exc

    def _fill_content(self, model: WebdavFile, format: Optional[str], require_hash: bool) -> WebdavFile:
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
                entry = self._fill_content(entry, None, require_hash)
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
                if model.type == "notebook":
                    model = self._convert_to_notebook(model)
            elif model.format == "base64":
                model.content = base64.b64encode(bytes_content).decode("ascii")
            if require_hash:
                h = hashlib.new(self.hash_algorithm)
                h.update(bytes_content)
                model.hash = h.hexdigest()
                model.hash_algorithm = self.hash_algorithm
        return model

    def get(self, path: str, content: bool = True, type: Optional[str] = None, format: Optional[str] = None, require_hash: bool = False):
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

        if content:
            model = self._fill_content(model, format, require_hash)

        self.emit(data={"action": "get", "path": path})
        return asdict(model)

    def save(self, model: Dict[str, Any], path: str):
        pymodel = WebdavFile(**model)
        raise NotImplementedError
    
    def delete_file(self, path: str):
        """Delete file at path."""
        if not self.allow_hidden and self.is_hidden(path):
            raise web.HTTPError(400, f"Cannot delete file or directory {path!r}")
        try:
            self._client.remove(path)
        except Exception as exc:
            raise web.HTTPError(400, f"Cannot delete file or directory {path!r}") from exc

    def rename_file(self, old_path: str, new_path: str):
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

    def file_exists(self, path: str = "") -> bool:
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

    def dir_exists(self, path: str) -> bool:
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

    def is_hidden(self, path: str) -> bool:
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
