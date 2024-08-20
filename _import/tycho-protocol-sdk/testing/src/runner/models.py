import difflib

from hexbytes import HexBytes
from pydantic import BaseModel, Field, validator
from typing import List, Dict, Optional

from tycho_client.dto import ProtocolComponent


class ProtocolComponentExpectation(BaseModel):
    """Represents a ProtocolComponent with its main attributes."""

    id: str = Field(..., description="Identifier of the protocol component")
    tokens: List[HexBytes] = Field(
        ...,
        description="List of token addresses associated with the protocol component",
    )
    static_attributes: Optional[Dict[str, HexBytes]] = Field(
        default_factory=dict, description="Static attributes of the protocol component"
    )
    creation_tx: HexBytes = Field(
        ..., description="Hash of the transaction that created the protocol component"
    )

    @validator("id", pre=True, always=True)
    def lower_id(cls, v):
        return v.lower()

    @validator("tokens", pre=True, always=True)
    def convert_tokens_to_hexbytes(cls, v):
        return sorted(HexBytes(t.lower()) for t in v)

    @validator("static_attributes", pre=True, always=True)
    def convert_static_attributes_to_hexbytes(cls, v):
        return {k: HexBytes(v[k].lower()) for k in v} if v else {}

    @validator("creation_tx", pre=True, always=True)
    def convert_creation_tx_to_hexbytes(cls, v):
        return HexBytes(v.lower())

    def compare(
        self, other: "ProtocolComponentExpectation", colorize_output: bool = True
    ) -> Optional[str]:
        """Compares the current instance with another ProtocolComponent instance and returns a message with the
        differences or None if there are no differences."""

        def colorize_diff(diff):
            colored_diff = []
            for line in diff:
                if line.startswith("-"):
                    colored_diff.append(f"\033[91m{line}\033[0m")  # Red
                elif line.startswith("+"):
                    colored_diff.append(f"\033[92m{line}\033[0m")  # Green
                elif line.startswith("?"):
                    colored_diff.append(f"\033[93m{line}\033[0m")  # Yellow
                else:
                    colored_diff.append(line)
            return "\n".join(colored_diff)

        differences = []
        for field_name, field_value in self.__dict__.items():
            other_value = getattr(other, field_name, None)
            if field_value != other_value:
                diff = list(difflib.ndiff([str(field_value)], [str(other_value)]))
                highlighted_diff = (
                    colorize_diff(diff) if colorize_output else "\n".join(diff)
                )
                differences.append(
                    f"Field '{field_name}' mismatch for {self.id}:\n{highlighted_diff}"
                )
        if not differences:
            return None

        return "\n".join(differences)


class ProtocolComponentWithTestConfig(ProtocolComponentExpectation):
    """Represents a ProtocolComponent with its main attributes and test configuration."""

    skip_simulation: Optional[bool] = Field(
        False,
        description="Flag indicating whether to skip simulation for this component",
    )


class IntegrationTest(BaseModel):
    """Configuration for an individual test."""

    name: str = Field(..., description="Name of the test")
    start_block: int = Field(..., description="Starting block number for the test")
    stop_block: int = Field(..., description="Stopping block number for the test")
    initialized_accounts: Optional[List[str]] = Field(
        None, description="List of initialized account addresses"
    )
    expected_components: List[ProtocolComponentWithTestConfig] = Field(
        ..., description="List of protocol components expected in the indexed state"
    )


class IntegrationTestsConfig(BaseModel):
    """Main integration test configuration."""

    substreams_yaml_path: str = Field(
        "./substreams.yaml", description="Path of the Substreams YAML file"
    )
    adapter_contract: str = Field(
        ..., description="Name of the SwapAdapter contract for this protocol"
    )
    adapter_build_signature: Optional[str] = Field(
        None, description="SwapAdapter's constructor signature"
    )
    adapter_build_args: Optional[str] = Field(
        None, description="Arguments for the SwapAdapter constructor"
    )
    initialized_accounts: Optional[List[str]] = Field(
        None,
        description="List of initialized account addresses. These accounts will be initialized for every tests",
    )
    skip_balance_check: bool = Field(
        ..., description="Flag to skip balance check for all tests"
    )
    protocol_type_names: List[str] = Field(
        ..., description="List of protocol type names for the tested protocol"
    )
    tests: List[IntegrationTest] = Field(..., description="List of integration tests")
