from pathlib import Path
from typing import List
import hashlib
import json

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

KNOWLEDGE_DIR = BASE_DIR / "data" / "knowledge_base"
VECTOR_DIR = BASE_DIR / "data" / "vectorstore"

INDEX_FILE = VECTOR_DIR / "trustiva.index"
METADATA_FILE = VECTOR_DIR / "metadata.json"

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


# ============================================================
# RAG SERVICE
# ============================================================

class RAGService:

    # Shared embedding model.
    # This prevents multiple copies from being loaded.
    _model = None

    def __init__(self):

        # ----------------------------------------------------
        # Load embedding model only once
        # ----------------------------------------------------

        if RAGService._model is None:

            print(
                "\nLoading Trustiva embedding model..."
            )

            RAGService._model = SentenceTransformer(
                MODEL_NAME
            )

            print(
                "Trustiva embedding model loaded."
            )

        self.model = RAGService._model

        self.documents = []
        self.index = None

        # ----------------------------------------------------
        # Prepare directories
        # ----------------------------------------------------

        KNOWLEDGE_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        VECTOR_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        # ----------------------------------------------------
        # Load or build vector index
        # ----------------------------------------------------

        self.load_or_build_index()

    # ========================================================
    # KNOWLEDGE BASE FINGERPRINT
    # ========================================================

    def calculate_knowledge_hash(self) -> str:

        """
        Creates a hash representing the current knowledge base.

        If any knowledge-base file changes, the hash changes
        and Trustiva automatically rebuilds the FAISS index.
        """

        hasher = hashlib.sha256()

        files = sorted(
            KNOWLEDGE_DIR.glob("*.txt")
        )

        for file_path in files:

            hasher.update(
                file_path.name.encode("utf-8")
            )

            content = file_path.read_bytes()

            hasher.update(content)

        return hasher.hexdigest()

    # ========================================================
    # LOAD KNOWLEDGE DOCUMENTS
    # ========================================================

    def load_documents(self):

        documents = []

        files = sorted(
            KNOWLEDGE_DIR.glob("*.txt")
        )

        for file_path in files:

            text = file_path.read_text(
                encoding="utf-8"
            )

            chunks = self.chunk_text(
                text
            )

            for chunk in chunks:

                documents.append(
                    {
                        "text": chunk,
                        "source": file_path.name,
                    }
                )

        return documents

    # ========================================================
    # LOAD OR BUILD INDEX
    # ========================================================

    def load_or_build_index(self):

        current_hash = (
            self.calculate_knowledge_hash()
        )

        # ----------------------------------------------------
        # Check whether an existing index can be reused
        # ----------------------------------------------------

        if (
            INDEX_FILE.exists()
            and METADATA_FILE.exists()
        ):

            try:

                metadata = json.loads(
                    METADATA_FILE.read_text(
                        encoding="utf-8"
                    )
                )

                stored_hash = metadata.get(
                    "knowledge_hash"
                )

                if stored_hash == current_hash:

                    print(
                        "Loading existing Trustiva "
                        "FAISS index..."
                    )

                    self.index = faiss.read_index(
                        str(INDEX_FILE)
                    )

                    self.documents = metadata.get(
                        "documents",
                        []
                    )

                    print(
                        "Existing FAISS index loaded."
                    )

                    return

                print(
                    "Knowledge base changed."
                )

                print(
                    "Rebuilding FAISS index..."
                )

            except Exception as error:

                print(
                    "Existing vector index could "
                    "not be loaded."
                )

                print(
                    f"Reason: {error}"
                )

                print(
                    "Rebuilding FAISS index..."
                )

        # ----------------------------------------------------
        # Build new index
        # ----------------------------------------------------

        self.build_index(
            current_hash
        )

    # ========================================================
    # BUILD INDEX
    # ========================================================

    def build_index(
        self,
        knowledge_hash: str
    ):

        print(
            "Reading Trustiva knowledge base..."
        )

        self.documents = (
            self.load_documents()
        )

        if not self.documents:

            print(
                "No knowledge-base documents found."
            )

            self.index = None

            return

        print(
            f"Found {len(self.documents)} "
            f"knowledge chunks."
        )

        # ----------------------------------------------------
        # Generate embeddings
        # ----------------------------------------------------

        print(
            "Generating knowledge embeddings..."
        )

        embeddings = self.model.encode(
            [
                document["text"]
                for document in self.documents
            ],
            convert_to_numpy=True,
            show_progress_bar=True,
        )

        embeddings = embeddings.astype(
            "float32"
        )

        # ----------------------------------------------------
        # Create FAISS index
        # ----------------------------------------------------

        dimension = embeddings.shape[1]

        self.index = faiss.IndexFlatL2(
            dimension
        )

        self.index.add(
            embeddings
        )

        # ----------------------------------------------------
        # Save FAISS index
        # ----------------------------------------------------

        faiss.write_index(
            self.index,
            str(INDEX_FILE)
        )

        # ----------------------------------------------------
        # Save metadata
        # ----------------------------------------------------

        metadata = {
            "knowledge_hash": knowledge_hash,
            "model": MODEL_NAME,
            "document_count": len(
                self.documents
            ),
            "documents": self.documents,
        }

        METADATA_FILE.write_text(
            json.dumps(
                metadata,
                ensure_ascii=False,
                indent=2
            ),
            encoding="utf-8"
        )

        print(
            "Trustiva FAISS index saved."
        )

    # ========================================================
    # TEXT CHUNKING
    # ========================================================

    @staticmethod
    def chunk_text(
        text: str,
        chunk_size: int = 700
    ) -> List[str]:

        words = text.split()

        chunks = []

        for i in range(
            0,
            len(words),
            chunk_size
        ):

            chunk = " ".join(
                words[
                    i:i + chunk_size
                ]
            )

            if chunk.strip():

                chunks.append(
                    chunk.strip()
                )

        return chunks

    # ========================================================
    # SEARCH
    # ========================================================

    def search(
        self,
        query: str,
        top_k: int = 3
    ):

        if self.index is None:

            return []

        if not self.documents:

            return []

        # ----------------------------------------------------
        # Convert query to embedding
        # ----------------------------------------------------

        query_embedding = self.model.encode(
            [query],
            convert_to_numpy=True,
            show_progress_bar=False,
        ).astype(
            "float32"
        )

        # ----------------------------------------------------
        # FAISS search
        # ----------------------------------------------------

        distances, indices = (
            self.index.search(
                query_embedding,
                min(
                    top_k,
                    len(self.documents)
                )
            )
        )

        results = []

        for distance, index in zip(
            distances[0],
            indices[0]
        ):

            if index < 0:

                continue

            document = self.documents[
                index
            ]

            results.append(
                {
                    "source": document[
                        "source"
                    ],
                    "text": document[
                        "text"
                    ],
                    "distance": float(
                        distance
                    ),
                }
            )

        return results